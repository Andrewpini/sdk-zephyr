
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
#include "proxy_client.h"
#include "rpl.h"

#define PROXY_SAR_TIMEOUT  K_SECONDS(20)
#define SERVER_BUF_SIZE 68

// ------------- Forward Declarations -------------

static int proxy_send(struct bt_conn *conn, const void *data,
		      uint16_t len);

// ------------- Parameters -------------

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
static uint16_t listen_netidx = 0; // TODO: Change from static
static struct bt_gatt_exchange_params exchange_params;

// ------------- Functions -------------

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

void bt_mesh_proxy_client_process(const bt_addr_le_t *addr, int8_t rssi,
				  struct net_buf_simple *buf)
{
	struct bt_mesh_subnet *sub;
	struct proxy_beacon beacon = { 0 };

	bt_data_parse(buf, beacon_process, (void *)&beacon);

	if (beacon.beacon_type == NONE) {
		return;
	}

	switch (beacon.beacon_type) {
	case NET:
		if (proxy_cb && proxy_cb->network_id) {
		BT_DBG("Incoming Net Id beacon");
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

	// TODO: Send to receive function

	return BT_GATT_ITER_CONTINUE;
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
			// TODO: Set filtertype of server
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

static void network_id_cb(const bt_addr_le_t *addr, uint16_t net_idx)
{
	// TODO: Make connection through net_id configurable
	int err;

	BT_DBG("Incoming net adv");
	if(bt_conn_lookup_addr_le(BT_ID_DEFAULT, addr)){
		BT_DBG("Allready found address");
		return;
	}

	BT_DBG("network_id_cb: net_idx: %d", net_idx);
	bt_mesh_scan_disable();
	err = bt_mesh_proxy_connect(addr, net_idx);

	if (err)
	{
		bt_mesh_scan_enable();
	}


}

static void node_id_cb(const bt_addr_le_t *addr, uint16_t net_idx,
		  uint16_t node_addr)
{
}

static struct bt_mesh_proxy proxy_cb_func = {
	.network_id = network_id_cb,
	.node_id = node_id_cb,
};

int bt_mesh_proxy_client_init(void)
{
	int i;

	/* Initialize the client receive buffers */
	BT_DBG("Starting Proxy Client");
	for (i = 0; i < ARRAY_SIZE(servers); i++) {
		struct bt_mesh_proxy_server *server = &servers[i];
		server->object.buf.size = SERVER_BUF_SIZE;
		server->object.buf.__buf = server_buf_data + (i * SERVER_BUF_SIZE);
		k_delayed_work_init(&server->object.sar_timer, proxy_sar_timeout);
	}

	bt_conn_cb_register(&conn_callbacks);
	proxy_cb = &proxy_cb_func;
	return 0;
}