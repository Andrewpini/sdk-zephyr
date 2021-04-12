#ifndef BT_MESH_PROXY_CLI_H__
#define BT_MESH_PROXY_CLI_H__

#include <bluetooth/bluetooth.h>
#include <net/buf.h>

#ifdef __cplusplus
extern "C" {
#endif

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

struct node_id_lookup {
	uint8_t addr;
	uint8_t net_idx;
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
	void (*connected)(struct bt_conn *conn, struct node_id_lookup *addr_ctx, uint8_t reason);

	/** @brief A new proxy connection has been configured.
	 *
	 *  This callback notifies the application of a new connection.
	 *  In case the err parameter is non-zero it means that the
	 *  connection establishment failed.
	 *
	 *  @param conn New connection object.
	 *  @param err  Zero for success, non-zero otherwise.
	 */
	void (*configured)(struct bt_conn *conn, struct node_id_lookup *addr_ctx);

	/** @brief A proxy connection has been disconnected.
	 *
	 *  This callback notifies the application that a proxy connection
	 *  has been disconnected.
	 *
	 *  @param conn Connection object.
	 *  @param reason reason for the disconnection.
	 */
	void (*disconnected)(struct bt_conn *conn,
			     struct node_id_lookup *addr_ctx, uint8_t reason);
};

void bt_mesh_proxy_cli_adv_relay_set(bool onoff);

bool bt_mesh_proxy_cli_is_adv_relay_enabled(void);

void bt_mesh_proxy_cli_conn_cb_set(
	void (*connected)(struct bt_conn *conn, struct node_id_lookup *addr_ctx,
			  uint8_t reason),
	void (*configured)(struct bt_conn *conn, struct node_id_lookup *addr_ctx),
	void (*disconnected)(struct bt_conn *conn,
			     struct node_id_lookup *addr_ctx, uint8_t reason));

void bt_mesh_proxy_client_process(const bt_addr_le_t *addr, int8_t rssi,
				  struct net_buf_simple *buf);

void bt_mesh_proxy_cli_node_id_connect(struct node_id_lookup *ctx);

bool bt_mesh_proxy_cli_relay(struct net_buf_simple *buf, uint16_t dst);

void bt_mesh_proxy_cli_net_id_connect(uint16_t net_idx);

int bt_mesh_proxy_client_init(void);

#ifdef __cplusplus
}
#endif

#endif /* BT_MESH_PROXY_CLI_H__ */