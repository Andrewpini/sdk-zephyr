
#include <zephyr.h>
#include <sys/byteorder.h>
#include <sys/util.h>

#include <net/buf.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/conn.h>
#include <bluetooth/gatt.h>
#include <bluetooth/mesh.h>

#define BT_DBG_ENABLED IS_ENABLED(CONFIG_BT_MESH_DEBUG_PROXY_CLIENT)
#define LOG_MODULE_NAME bt_mesh_proxy_client
#include "common/log.h"

#include "mesh.h"
#include "adv.h"
#include "net.h"
#include "prov.h"
#include "beacon.h"
#include "foundation.h"
#include "access.h"
// #include "proxy_common.h"
#include "proxy_client.h"
#include "rpl.h"


#define SERVER_BUF_SIZE 68

/* ------------------------------------------------------------------------------------------------------------------ */

#define SAR_COMPLETE       0x00
#define SAR_FIRST          0x01
#define SAR_CONT           0x02
#define SAR_LAST           0x03

#define BT_MESH_PROXY_NET_PDU   0x00
#define BT_MESH_PROXY_BEACON    0x01
#define BT_MESH_PROXY_CONFIG    0x02
#define BT_MESH_PROXY_PROV      0x03

#define CFG_FILTER_SET     0x00
#define CFG_FILTER_ADD     0x01
#define CFG_FILTER_REMOVE  0x02
#define CFG_FILTER_STATUS  0x03

#define PROXY_SAR_TIMEOUT  K_SECONDS(20)
#define PDU_SAR(data)      (data[0] >> 6)
#define PDU_HDR(sar, type) (sar << 6 | (type & BIT_MASK(6)))
#define PDU_TYPE(data)     (data[0] & BIT_MASK(6))

static uint16_t listen_netidx;
static struct bt_gatt_exchange_params exchange_params;

typedef int (*proxy_send_cb_t)(struct bt_conn *conn, const void *data,
			       uint16_t len);

typedef void (*proxy_recv_cb_t)(struct bt_conn *conn,
				struct bt_mesh_net_rx *rx, struct net_buf_simple *buf);

struct bt_mesh_proxy_object {
	struct bt_conn *conn;
	uint8_t msg_type;
	struct {
		proxy_send_cb_t send_cb;
		proxy_recv_cb_t recv_cb;
	} cb;
	struct k_delayed_work sar_timer;
	struct net_buf_simple buf;
};

/** Proxy Client Callbacks. */
struct bt_mesh_proxy {
	/** @brief Proxy Network Identity Beacon has been received.
	 *
	 *  This callback notifies the application that Proxy Network
	 *  Identity Beacon has been received.
	 *
	 *  @param addr Remote Bluetooth address.
	 *  @param net_idx NetKeyIndex.
	 */
	void (*network_id)(const bt_addr_le_t *addr, uint16_t net_idx);

	/** @brief Proxy Node Identity Beacon has been received.
	 *
	 *  This callback notifies the application that Node Network
	 *  Identity Beacon has been received.
	 *
	 *  @param addr Remote Bluetooth address.
	 *  @param net_idx NetKeyIndex.
	 *  @param node_addr Node Address.
	 */
	void (*node_id)(const bt_addr_le_t *addr, uint16_t net_idx,
			uint16_t node_addr);

	/** @brief A new proxy connection has been established.
	 *
	 *  This callback notifies the application of a new connection.
	 *  In case the err parameter is non-zero it means that the
	 *  connection establishment failed.
	 *
	 *  @param conn New connection object.
	 *  @param err  Zero for success, non-zero otherwise.
	 */
	void (*connected)(struct bt_conn *conn, uint8_t reason);

	/** @brief A proxy connection has been disconnected.
	 *
	 *  This callback notifies the application that a proxy connection
	 *  has been disconnected.
	 *
	 *  @param conn Connection object.
	 *  @param reason reason for the disconnection.
	 */
	void (*disconnected)(struct bt_conn *conn, uint8_t reason);
};

/** @brief Register a structure for Proxy Client notification to application.
 *
 *  Registers a callback that will be called whenever Proxy Client received
 *  vaild nerwork identity beacon or node identity beacon.
 *
 *  @param cb Callback struct.
 */
void bt_mesh_proxy_client_set_cb(struct bt_mesh_proxy *cb);

/** @brief Initiate an proxy connection to a remote device.
 *
 *  Initiate an proxy connection to a remote device, discovery services and
 *  open the notification.
 *
 *  @param addr Remote address.
 *  @param net_idx NetKeyIndex.
 *
 *  @return Zero on success or (negative) error code on failure.
 */
int bt_mesh_proxy_connect(const bt_addr_le_t *addr, uint16_t net_idx);

static void exchange_func(struct bt_conn *conn, uint8_t err,
			  struct bt_gatt_exchange_params *params)
{
	BT_DBG("MTU exchange %s", err == 0 ? "successful" : "failed");
	BT_DBG("Current MTU: %u", bt_gatt_get_mtu(conn));
}

static void proxy_sar_timeout(struct k_work *work)
{
	struct bt_mesh_proxy_object *object;

	BT_WARN("Proxy SAR timeout");

	object = CONTAINER_OF(work, struct bt_mesh_proxy_object, sar_timer);
	if (object->conn) {
		bt_conn_disconnect(object->conn,
				   BT_HCI_ERR_REMOTE_USER_TERM_CONN);
	}
}

static void bt_mesh_proxy_common_init(struct bt_mesh_proxy_object *object,
			       uint8_t *buf, uint16_t len)
{
	object->buf.size = len;
	object->buf.__buf = buf;

	k_delayed_work_init(&object->sar_timer, proxy_sar_timeout);
}

/* ------------------------------------------------------------------------------------------------------------------ */

static int proxy_send(struct bt_conn *conn, const void *data,
		      uint16_t len);

static struct bt_mesh_proxy_server {
	struct bt_mesh_proxy_object object;
	enum {
		SR_NONE,
		SR_PROV,
		SR_NETWORK,
	} type;

	uint16_t net_idx;
	uint16_t cmd_handle;
	struct bt_uuid_16 uuid;
	struct bt_gatt_discover_params discover_params;
	struct bt_gatt_subscribe_params subscribe_params;
} servers[CONFIG_BT_MAX_CONN] = {
	[0 ... (CONFIG_BT_MAX_CONN - 1)] = {
		.net_idx = BT_MESH_KEY_UNUSED,
		.object.cb = {
			.send_cb = proxy_send,
		}
	}
};

static struct bt_mesh_proxy *proxy_cb;
static uint8_t __noinit server_buf_data[SERVER_BUF_SIZE * CONFIG_BT_MAX_CONN];

static struct bt_mesh_proxy_server *find_server(struct bt_conn *conn)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(servers); i++) {
		if (servers[i].object.conn == conn) {
			return &servers[i];
		}
	}

	return NULL;
}

struct proxy_beacon {
	uint8_t count;
	enum {
		NONE,
		PROV,
		NET,
		NODE,
	} beacon_type;
	union {
		struct provision {
			const uint8_t *uuid;
			const uint8_t *oob;
		} prov;

		struct network_id {
			const uint8_t *id;
		} net;

		struct node_id {
			const uint8_t *hash;
			const uint8_t *random;
		} node;
	};
};

static bool beacon_process(struct bt_data *data, void *user_data)
{
	struct bt_uuid uuid;
	struct proxy_beacon *beacon = user_data;

	// BT_DBG("[AD]: %u data_len %u", data->type, data->data_len);

	switch (data->type) {
	case BT_DATA_FLAGS:
		if (data->data_len != 1U || beacon->count) {
			goto failed;
		}
		break;
	case BT_DATA_UUID16_SOME:
	case BT_DATA_UUID16_ALL:
		if (data->data_len != 2U || beacon->count != 1U) {
			goto failed;
		}

		bt_uuid_create(&uuid, data->data, 2);
		if (!bt_uuid_cmp(&uuid, BT_UUID_MESH_PROV)) {
			beacon->beacon_type = PROV;
		} else if (!bt_uuid_cmp(&uuid, BT_UUID_MESH_PROXY)) {
			beacon->beacon_type = NET;
		} else {
			beacon->beacon_type = NONE;
			goto failed;
		}

		break;
	case BT_DATA_SVC_DATA16:
		if (beacon->count != 2U) {
			goto failed;
		}

		if (beacon->beacon_type == PROV) {
			BT_DBG("Incoming provisioning beacon");
			if (data->data_len != 20U) {
				goto failed;
			}

			bt_uuid_create(&uuid, data->data, 2);
			if (bt_uuid_cmp(&uuid, BT_UUID_MESH_PROV)) {
				goto failed;
			}

			beacon->prov.uuid = &data->data[2];
			beacon->prov.oob = &data->data[18];
			return true;
		} else if (beacon->beacon_type == NET) {
			if (data->data_len == 11U) {
				bt_uuid_create(&uuid, data->data, 2);
				if (bt_uuid_cmp(&uuid, BT_UUID_MESH_PROXY)) {
					goto failed;
				}

				if (data->data[2] != 0x00) {
					goto failed;
				}

				beacon->beacon_type = NET;
				beacon->net.id = &data->data[3];
				return true;
			} else if (data->data_len == 19U) {
				bt_uuid_create(&uuid, data->data, 2);
				if (bt_uuid_cmp(&uuid, BT_UUID_MESH_PROXY)) {
					goto failed;
				}

				if (data->data[2] != 0x01) {
					goto failed;
				}

				beacon->beacon_type = NODE;
				beacon->node.hash = &data->data[3];
				beacon->node.random = &data->data[11];
				return true;
			}
		}
		__fallthrough;
	default:
		goto failed;
	}

	beacon->count++;
	return true;

failed:
	beacon->beacon_type = NONE;
	return false;
}

struct node_user_data {
	const uint8_t *random;
	const uint8_t *hash;
	struct bt_mesh_cdb_node *node;
};

static uint8_t node_id_find(struct bt_mesh_cdb_node *node,
			    void *user_data)
{
	int err;
	uint8_t tmp[16];
	struct bt_mesh_subnet *sub;
	struct node_user_data *ud = user_data;

	(void)memset(tmp, 0, 6);
	memcpy(tmp + 6, ud->random, 8);
	sys_put_be16(node->addr, &tmp[14]);

	sub = bt_mesh_subnet_get(node->net_idx);
	if (sub == NULL) {
		ud->node = NULL;
		return BT_MESH_CDB_ITER_STOP;
	}

	err = bt_encrypt_be(sub->keys[SUBNET_KEY_TX_IDX(sub)].identity, tmp, tmp);
	if (err) {
		ud->node = NULL;
		return BT_MESH_CDB_ITER_STOP;
	}

	if (!memcmp(ud->hash, tmp + 8, 8)) {
		ud->node = node;
		return BT_MESH_CDB_ITER_STOP;
	}

	return BT_MESH_CDB_ITER_CONTINUE;
}

void bt_mesh_proxy_client_process(const bt_addr_le_t *addr, int8_t rssi,
				  struct net_buf_simple *buf)
{
	struct bt_mesh_subnet *sub;
	struct node_user_data user_data;
	struct proxy_beacon beacon = { 0 };

	bt_data_parse(buf, beacon_process, (void *)&beacon);

	if (beacon.beacon_type == NONE) {
		return;
	}

	switch (beacon.beacon_type) {
	case NET:
		if (proxy_cb && proxy_cb->network_id) {
			sub = bt_mesh_subnet_get(listen_netidx);

			if (!sub) {
				break;
			} else if (!memcmp(beacon.net.id,
					   sub->keys[0].net_id, 8)) {
				proxy_cb->network_id(addr, sub->net_idx);
			} else if (sub->kr_phase ==
				   BT_MESH_KR_NORMAL) {
				break;
			} else if (!memcmp(beacon.net.id,
					   sub->keys[1].net_id, 8)) {
				proxy_cb->network_id(addr, sub->net_idx);
			}
		}
		break;
	case NODE:
		if (proxy_cb && proxy_cb->node_id) {
			user_data.random = beacon.node.random;
			user_data.hash = beacon.node.hash;
			user_data.node = NULL;
			// bt_mesh_cdb_node_foreach(node_id_find, &user_data);
			if (user_data.node) {
				proxy_cb->node_id(addr, user_data.node->net_idx,
						  user_data.node->addr);
			}
		}
		break;
	default:
		break;
	}
}

int bt_mesh_proxy_connect(const bt_addr_le_t *addr, uint16_t net_idx)
{
	int err;
	struct bt_le_conn_param *param;
	struct bt_mesh_proxy_server *server = find_server(NULL);

	if (!server) {
		BT_ERR("No server object available");
		return -ENOBUFS;
	}

	server->net_idx = net_idx;
	server->type = SR_NETWORK;

	param = BT_LE_CONN_PARAM_DEFAULT;
	err = bt_conn_le_create(addr, BT_CONN_LE_CREATE_CONN,
				param, &server->object.conn);
	if (err) {
		BT_ERR("Create conn failed (err %d)", err);
		server->type = SR_NONE;
		server->net_idx = BT_MESH_KEY_UNUSED;
		return err;
	}

	return 0;
}

static void proxy_cfg(struct bt_mesh_proxy_object *object)
{
	NET_BUF_SIMPLE_DEFINE(buf, 29);
	struct bt_mesh_net_rx rx;
	int err;

	err = bt_mesh_net_decode(&object->buf, BT_MESH_NET_IF_PROXY_CFG,
				 &rx, &buf);
	if (err) {
		BT_ERR("Failed to decode Proxy Configuration (err %d)", err);
		return;
	}

	rx.local_match = 1U;

	if (bt_mesh_rpl_check(&rx, NULL)) {
		BT_WARN("Replay: src 0x%04x dst 0x%04x seq 0x%06x",
			rx.ctx.addr, rx.ctx.recv_dst, rx.seq);
		return;
	}

	/* Remove network headers */
	net_buf_simple_pull(&buf, BT_MESH_NET_HDR_LEN);

	BT_DBG("%u bytes: %s", buf.len, bt_hex(buf.data, buf.len));

	if (buf.len < 1) {
		BT_WARN("Too short proxy configuration PDU");
		return;
	}

	// if (object->cb.recv_cb) {
	// 	object->cb.recv_cb(object->conn, &rx, &buf);
	// }
}

static void proxy_complete_pdu(struct bt_mesh_proxy_object *object)
{
	switch (object->msg_type) {
#if defined(CONFIG_BT_MESH_GATT_PROXY)
	case BT_MESH_PROXY_NET_PDU:
		BT_DBG("CLI Mesh Network PDU");
		bt_mesh_net_recv(&object->buf, 0, BT_MESH_NET_IF_PROXY);
		break;
	case BT_MESH_PROXY_BEACON:
		BT_DBG("Mesh Beacon PDU");
		bt_mesh_beacon_recv(&object->buf);
		break;
#endif
#if defined(CONFIG_BT_MESH_GATT_PROXY) || \
	defined(CONFIG_BT_MESH_PROXY_CLIENT)
	case BT_MESH_PROXY_CONFIG:
		BT_DBG("Mesh Configuration PDU");
		proxy_cfg(object);
		break;
#endif
#if defined(CONFIG_BT_MESH_PB_GATT)
	case BT_MESH_PROXY_PROV:
		BT_DBG("Mesh Provisioning PDU");
		bt_mesh_pb_gatt_recv(object->conn, &object->buf);
		break;
#endif
	default:
		BT_WARN("Unhandled Message Type 0x%02x", object->msg_type);
		break;
	}

	net_buf_simple_reset(&object->buf);
}

int bt_mesh_proxy_cli_recv(struct bt_mesh_proxy_object *object,
			      const void *buf, uint16_t len)
{
	const uint8_t *data = buf;

	switch (PDU_SAR(data)) {
	case SAR_COMPLETE:
		if (object->buf.len) {
			BT_WARN("Complete PDU while a pending incomplete one");
			return -EINVAL;
		}

		object->msg_type = PDU_TYPE(data);
		net_buf_simple_add_mem(&object->buf, data + 1, len - 1);
		proxy_complete_pdu(object);
		break;

	case SAR_FIRST:
		if (object->buf.len) {
			BT_WARN("First PDU while a pending incomplete one");
			return -EINVAL;
		}

		k_delayed_work_submit(&object->sar_timer, PROXY_SAR_TIMEOUT);
		object->msg_type = PDU_TYPE(data);
		net_buf_simple_add_mem(&object->buf, data + 1, len - 1);
		break;

	case SAR_CONT:
		if (!object->buf.len) {
			BT_WARN("Continuation with no prior data");
			return -EINVAL;
		}

		if (object->msg_type != PDU_TYPE(data)) {
			BT_WARN("Unexpected message type in continuation");
			return -EINVAL;
		}

		k_delayed_work_submit(&object->sar_timer, PROXY_SAR_TIMEOUT);
		net_buf_simple_add_mem(&object->buf, data + 1, len - 1);
		break;

	case SAR_LAST:
		if (!object->buf.len) {
			BT_WARN("Last SAR PDU with no prior data");
			return -EINVAL;
		}

		if (object->msg_type != PDU_TYPE(data)) {
			BT_WARN("Unexpected message type in last SAR PDU");
			return -EINVAL;
		}

		k_delayed_work_cancel(&object->sar_timer);
		net_buf_simple_add_mem(&object->buf, data + 1, len - 1);
		proxy_complete_pdu(object);
		break;
	}

	return len;
}

static uint8_t proxy_notify_func(struct bt_conn *conn,
				 struct bt_gatt_subscribe_params *params,
				 const void *data, uint16_t length)
{
	struct bt_mesh_proxy_server *server;
	BT_DBG("CLI Incoming notification: %s", bt_hex(data, length));
	if (!data) {
		BT_ERR("[UNSUBSCRIBED]\n");
		bt_conn_disconnect(conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
		return BT_GATT_ITER_STOP;
	}

	server = find_server(conn);
	if (!server) {
		BT_ERR("Unabled find server object");
		bt_conn_disconnect(conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
		return BT_GATT_ITER_STOP;
	}

	bt_mesh_proxy_cli_recv(&server->object, data, length);

	return BT_GATT_ITER_CONTINUE;
}

static int proxy_send(struct bt_conn *conn, const void *data,
		      uint16_t len)
{
	struct bt_mesh_proxy_server *server;

	server = find_server(conn);
	if (!server) {
		BT_ERR("Unabled find server object");
		return -ENOTCONN;
	}

	if (!server->cmd_handle) {
		BT_ERR("Not Preform Services Discovery");
		return -ENOTSUP;
	}

	return bt_gatt_write_without_response(conn, server->cmd_handle,
					      data, len, false);
}


static int proxy_client_send(struct bt_mesh_proxy_server *srv, const void *data,
			     uint16_t length)
{
	int err = bt_gatt_write_without_response_cb(srv->object.conn,
						    srv->cmd_handle, data,
						    length, false, NULL, NULL);
	return err;
}

static int proxy_segment_and_send(struct bt_mesh_proxy_server *srv, uint8_t type,
				  struct net_buf_simple *msg)
{
	uint16_t mtu;

	BT_DBG("proxy_segment_and_send: conn %p type 0x%02x len %u: %s", srv->object.conn, type, msg->len,
	       bt_hex(msg->data, msg->len));

	/* ATT_MTU - OpCode (1 byte) - Handle (2 bytes) */
	mtu = bt_gatt_get_mtu(srv->object.conn) - 3;
	if (mtu > msg->len) {
		net_buf_simple_push_u8(msg, PDU_HDR(SAR_COMPLETE, type));
		return proxy_client_send(srv, msg->data, msg->len);
	}

	net_buf_simple_push_u8(msg, PDU_HDR(SAR_FIRST, type));
	proxy_client_send(srv, msg->data, mtu);
	net_buf_simple_pull(msg, mtu);

	while (msg->len) {
		if (msg->len + 1 < mtu) {
			net_buf_simple_push_u8(msg, PDU_HDR(SAR_LAST, type));
			proxy_client_send(srv, msg->data, msg->len);
			break;
		}

		net_buf_simple_push_u8(msg, PDU_HDR(SAR_CONT, type));
		proxy_client_send(srv, msg->data, mtu);
		net_buf_simple_pull(msg, mtu);
	}

	return 0;
}

static int bt_mesh_proxy_send(struct bt_conn *conn, uint8_t type,
		       struct net_buf_simple *msg)
{
	struct bt_mesh_proxy_server *srv = find_server(conn);

	if (!srv) {
		BT_ERR("No Proxy Server found");
		return -ENOTCONN;
	}

	if ((srv->type == SR_PROV) != (type == BT_MESH_PROXY_PROV)) {
		BT_ERR("Invalid PDU type for Proxy Server");
		return -EINVAL;
	}

	return proxy_segment_and_send(srv, type, msg);
}

static void filter_cmd_send(struct bt_mesh_proxy_server *srv,
			       struct net_buf_simple *buf)
{
		struct bt_mesh_msg_ctx ctx = {
		.net_idx = srv->net_idx,
		.app_idx = BT_MESH_KEY_UNUSED,
		.addr = BT_MESH_ADDR_UNASSIGNED,
		.send_ttl = 0,
		};

	struct bt_mesh_net_tx tx = {
		.sub = bt_mesh_subnet_get(srv->net_idx),
		.ctx = &ctx,
		.src = bt_mesh_primary_addr(),
	};
	int err;

	err = bt_mesh_net_encode(&tx, buf, true);
	if (err) {
		BT_ERR("Encoding Proxy cfg message failed (err %d)", err);
		return;
	}

	err = proxy_segment_and_send(srv, BT_MESH_PROXY_CONFIG, buf);
	if (err) {
		BT_ERR("Failed to send proxy cfg message (err %d)", err);
	}
}

static void filter_type_set(struct bt_mesh_proxy_server *srv, bool is_blacklist)
{
	NET_BUF_SIMPLE_DEFINE(buf, 19 + 2);
	net_buf_simple_reserve(&buf, 10);
	net_buf_simple_add_u8(&buf, CFG_FILTER_SET);
	net_buf_simple_add_u8(&buf, (is_blacklist ? 1 : 0));

	BT_DBG("filter_type_set %u bytes: %s", buf.len,
	       bt_hex(buf.data, buf.len));

	filter_cmd_send(srv, &buf);
}

static void filter_addr_add(struct bt_mesh_proxy_server *srv,
			    uint16_t *addr_arr, uint16_t len)
{
	NET_BUF_SIMPLE_DEFINE(buf, 19 + 1 + len);
	net_buf_simple_reserve(&buf, 10);
	net_buf_simple_add_u8(&buf, CFG_FILTER_ADD);

	for (size_t i = 0; i < (len / sizeof(addr_arr[0])); i++)
	{
		net_buf_simple_add_be16(&buf, addr_arr[i]);
	}

	BT_DBG("filter_addr_add %u bytes: %s", buf.len, bt_hex(buf.data, buf.len));

	filter_cmd_send(srv, &buf);
}

static void filter_addr_remove(struct bt_mesh_proxy_server *srv,
			       uint16_t *addr_arr, uint16_t len)
{
	NET_BUF_SIMPLE_DEFINE(buf, 19 + 1 + len);
	net_buf_simple_reserve(&buf, 10);
	net_buf_simple_add_u8(&buf, CFG_FILTER_REMOVE);

	for (size_t i = 0; i < (len / sizeof(addr_arr[0])); i++)
	{
		net_buf_simple_add_be16(&buf, addr_arr[i]);
	}

	BT_DBG("filter_addr_remove %u bytes: %s", buf.len, bt_hex(buf.data, buf.len));

	filter_cmd_send(srv, &buf);
}


static uint8_t proxy_discover_func(struct bt_conn *conn,
				   const struct bt_gatt_attr *attr,
				   struct bt_gatt_discover_params *params)
{
	int err;
	struct bt_mesh_proxy_server *server;
	struct bt_gatt_discover_params *discover_params;
	struct bt_gatt_subscribe_params *subscribe_params;
	struct bt_uuid_16 serv_uuid, char_in_uuid, char_out_uuid;

	if (!attr) {
		BT_DBG("Discover complete");
		(void)memset(params, 0, sizeof(*params));
		return BT_GATT_ITER_STOP;
	}

	server = find_server(conn);
	if (!server) {
		BT_ERR("Unabled find server object");
		bt_conn_disconnect(conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
		return BT_GATT_ITER_STOP;
	}

	BT_DBG("[ATTRIBUTE] handle %u", attr->handle);

	if (server->type == SR_NETWORK) {
		memcpy(&serv_uuid, BT_UUID_MESH_PROXY, sizeof(serv_uuid));
		memcpy(&char_in_uuid, BT_UUID_MESH_PROXY_DATA_IN,
		       sizeof(char_in_uuid));
		memcpy(&char_out_uuid, BT_UUID_MESH_PROXY_DATA_OUT,
		       sizeof(char_out_uuid));
	} else {
		memcpy(&serv_uuid, BT_UUID_MESH_PROV, sizeof(serv_uuid));
		memcpy(&char_in_uuid, BT_UUID_MESH_PROV_DATA_IN,
		       sizeof(char_in_uuid));
		memcpy(&char_out_uuid, BT_UUID_MESH_PROV_DATA_OUT,
		       sizeof(char_out_uuid));
	}

	discover_params = &server->discover_params;
	subscribe_params = &server->subscribe_params;
	if (!bt_uuid_cmp(discover_params->uuid, &serv_uuid.uuid)) {
		memcpy(&server->uuid, &char_in_uuid, sizeof(server->uuid));
		discover_params->uuid = &server->uuid.uuid;
		discover_params->start_handle = attr->handle + 1;
		discover_params->type = BT_GATT_DISCOVER_CHARACTERISTIC;

		err = bt_gatt_discover(conn, discover_params);
		if (err) {
			BT_ERR("Discover failed (err %d)", err);
			bt_conn_disconnect(conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
		}
	} else if (!bt_uuid_cmp(discover_params->uuid,
				&char_in_uuid.uuid)) {
		server->cmd_handle = bt_gatt_attr_value_handle(attr);

		memcpy(&server->uuid, &char_out_uuid, sizeof(server->uuid));
		discover_params->uuid = &server->uuid.uuid;
		discover_params->start_handle = attr->handle + 1;
		discover_params->type = BT_GATT_DISCOVER_CHARACTERISTIC;

		err = bt_gatt_discover(conn, discover_params);
		if (err) {
			BT_ERR("Discover failed (err %d)", err);
			bt_conn_disconnect(conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
		}
	} else if (!bt_uuid_cmp(discover_params->uuid,
				&char_out_uuid.uuid)) {
		memcpy(&server->uuid, BT_UUID_GATT_CCC, sizeof(server->uuid));
		discover_params->uuid = &server->uuid.uuid;
		discover_params->start_handle = attr->handle + 2;
		discover_params->type = BT_GATT_DISCOVER_DESCRIPTOR;
		subscribe_params->value_handle = bt_gatt_attr_value_handle(attr);
		err = bt_gatt_discover(conn, discover_params);
		if (err) {
			BT_ERR("Discover failed (err %d)", err);
			bt_conn_disconnect(conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
		}
	} else if (!bt_uuid_cmp(discover_params->uuid,
				BT_UUID_GATT_CCC)) {
		subscribe_params->notify = proxy_notify_func;
		subscribe_params->value = BT_GATT_CCC_NOTIFY;
		subscribe_params->ccc_handle = attr->handle;

		err = bt_gatt_subscribe(conn, subscribe_params);
		if (err && err != -EALREADY) {
			BT_ERR("Subscribe failed (err %d)", err);
			bt_conn_disconnect(conn,
					   BT_HCI_ERR_REMOTE_USER_TERM_CONN);
		} else {
			BT_DBG("[SUBSCRIBED]");
			filter_type_set(server, true);

		}

		return BT_GATT_ITER_STOP;
	} else {
		BT_ERR("UnKnown");
		bt_conn_disconnect(conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
	}

	return BT_GATT_ITER_STOP;
}

static void proxy_connected(struct bt_conn *conn, uint8_t conn_err)
{
	int err;
	struct bt_mesh_proxy_server *server;
	struct bt_gatt_discover_params *params;
	struct bt_conn_info info;

	bt_conn_get_info(conn, &info);
	if (info.role != BT_CONN_ROLE_MASTER) {
		return;
	}

	server = find_server(conn);
	net_buf_simple_reset(&server->object.buf);

	if (conn_err) {
		BT_ERR("Failed to connect (%u)", conn_err);
		if (server) {
			bt_conn_unref(server->object.conn);
			server->object.conn = NULL;
		}

		if (proxy_cb && proxy_cb->connected) {
			proxy_cb->connected(conn, conn_err);
		}

		return;
	}

	if (!server) {
		BT_ERR("Unabled find server object");
		bt_conn_disconnect(conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
		return;
	}

	BT_DBG("Proxy connected");
	int test_err = bt_mesh_scan_enable();
	BT_DBG("bt_mesh_scan_enable: %d", test_err);
	if (proxy_cb && proxy_cb->connected) {
		proxy_cb->connected(conn, 0);
	}

	if (server->type == SR_NETWORK) {
		memcpy(&server->uuid, BT_UUID_MESH_PROXY, sizeof(server->uuid));
	} else {
		memcpy(&server->uuid, BT_UUID_MESH_PROV, sizeof(server->uuid));
	}

	exchange_params.func = exchange_func;
	err = bt_gatt_exchange_mtu(conn, &exchange_params);

	params = &server->discover_params;
	params->uuid = &server->uuid.uuid;
	params->func = proxy_discover_func;
	params->start_handle = 0x0001;
	params->end_handle = 0xffff;
	params->type = BT_GATT_DISCOVER_PRIMARY;

	err = bt_gatt_discover(conn, params);
	if (err) {
		BT_ERR("Discover failed(err %d)", err);
		bt_conn_disconnect(conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
		return;
	}
}

static void proxy_disconnected(struct bt_conn *conn, uint8_t reason)
{
	struct bt_mesh_proxy_server *server;
	struct bt_conn_info info;

	bt_conn_get_info(conn, &info);
	if (info.role != BT_CONN_ROLE_MASTER) {
		return;
	}

	server = find_server(conn);
	if (!server) {
		BT_ERR("Unabled find server object");
		return;
	}

	if (proxy_cb && proxy_cb->disconnected) {
		proxy_cb->disconnected(conn, reason);
	}

	server->type = SR_NONE;
	server->cmd_handle = 0U;
	server->net_idx = BT_MESH_KEY_UNUSED;
	bt_conn_unref(server->object.conn);
	server->object.conn = NULL;
	k_delayed_work_cancel(&server->object.sar_timer);

	BT_DBG("Disconnected (reason 0x%02x)", reason);
}

void bt_mesh_proxy_client_set_cb(struct bt_mesh_proxy *cb)
{
	proxy_cb = cb;
}

static struct bt_conn_cb conn_callbacks = {
	.connected = proxy_connected,
	.disconnected = proxy_disconnected,
};

// TODO: REMOVE AT SOME POINT
static void network_id_cb(const bt_addr_le_t *addr, uint16_t net_idx)
{
	int err;

	if(bt_conn_lookup_addr_le(BT_ID_DEFAULT, addr)){
		return;
	}

	// BT_DBG("network_id_cb: net_idx: %d", net_idx);
	bt_mesh_scan_disable();
	// bt_le_scan_stop();
	err = bt_mesh_proxy_connect(addr, net_idx);

	if (err)
	{
		bt_mesh_scan_enable();
	}


}

static struct bt_mesh_proxy proxy_cb_temp = {
	.network_id = network_id_cb,
};

void bt_mesh_proxy_client_subnet_listen_set(uint16_t net_idx)
{
	listen_netidx = net_idx;
}

#include <dk_buttons_and_leds.h>

void cb(struct bt_conn *conn, uint8_t err,
	struct bt_gatt_exchange_params *params)
{
}

struct bt_gatt_exchange_params asd;

bool bt_mesh_proxy_cli_relay(struct net_buf_simple *buf, uint16_t dst)
{
	bool relayed = false;

	BT_DBG("bt_mesh_proxy_relay CLI %u bytes to dst 0x%04x", buf->len, dst);

	for (int i = 0; i < ARRAY_SIZE(servers); i++) {
		if (!servers[i].object.conn) {
			continue;
		}

		NET_BUF_SIMPLE_DEFINE(msg, 32);

		/* Proxy PDU sending modifies the original buffer,
		 * so we need to make a copy.
		 */
		net_buf_simple_reserve(&msg, 1);
		net_buf_simple_add_mem(&msg, buf->data, buf->len);

		bt_mesh_proxy_send(servers[i].object.conn, BT_MESH_PROXY_NET_PDU, &msg);
		relayed = true;
	}

	return relayed;
}

static void button_changed(uint32_t button_state, uint32_t has_changed)
{
	if (button_state & BIT(0)) {
		printk("Button 1 pressed\n");
		for (int i = 0; i < ARRAY_SIZE(servers); i++) {
			if (servers[i].object.conn) {
				uint8_t test_arr[2] = { 0, 2 };
				uint8_t test_arr2[] = { 0x00, 0x2c, 0x31, 0xba,
							0x8d, 0xe4, 0xbc, 0xf9,
							0xab, 0x60, 0x31, 0x39,
							0x95, 0xf2, 0x04, 0x92,
							0xb4, 0x7d, 0xbd, 0x5c,
							0xe7 };
				int err = bt_gatt_write_without_response_cb(
					servers[i].object.conn,
					servers[i].cmd_handle, test_arr,
					sizeof(test_arr), false, NULL, NULL);
				err = bt_gatt_write_without_response_cb(
					servers[i].object.conn,
					servers[i].cmd_handle, test_arr2,
					sizeof(test_arr2), false, NULL, NULL);
				uint16_t mtu = bt_gatt_get_mtu(servers[i].object.conn);
				printk("MTU: %d\n", mtu);

				asd.func = cb;
				bt_gatt_exchange_mtu(servers[i].object.conn, &asd);
			}
		}
	}

	if (button_state & BIT(1)) {
		printk("Button 2 pressed\n");

		NET_BUF_SIMPLE_DEFINE(msg, 32);
		net_buf_simple_add_u8(&msg, 1);
		net_buf_simple_add_u8(&msg, 2);

		bt_mesh_proxy_cli_relay(&msg,1);

	}

	if (button_state & BIT(2)) {
		printk("Button 3 pressed\n");

		for (int i = 0; i < ARRAY_SIZE(servers); i++) {
			if (servers[i].object.conn) {
				filter_type_set(&servers[i], false);
				filter_type_set(&servers[i], true);
				uint16_t addr[3] = { 1, 2, 3};
				filter_addr_add(&servers[i], addr, sizeof(addr));
				filter_addr_remove(&servers[i], addr, sizeof(addr));
			}
		}
	}
}

int bt_mesh_proxy_client_init(void)
{
	int i;

	/* Initialize the client receive buffers */
	BT_DBG("Starting Proxy Client");
	for (i = 0; i < ARRAY_SIZE(servers); i++) {
		struct bt_mesh_proxy_server *server = &servers[i];

		// bt_mesh_proxy_common_init(&server->object,
		// 			  server_buf_data +
		// 				  (i * SERVER_BUF_SIZE),
		// 			  SERVER_BUF_SIZE);

		server->object.buf.size = SERVER_BUF_SIZE;
		server->object.buf.__buf = server_buf_data + (i * SERVER_BUF_SIZE);
		// client->buf.__buf = server_buf_data + (i * SERVER_BUF_SIZE);

		k_delayed_work_init(&server->object.sar_timer, proxy_sar_timeout);
	}

	bt_conn_cb_register(&conn_callbacks);

	// TODO: REMOVE AT SOME POINT
	// dk_buttons_init(button_changed);
	bt_mesh_proxy_client_subnet_listen_set(0);
	bt_mesh_proxy_client_set_cb(&proxy_cb_temp);
	return 0;
}
