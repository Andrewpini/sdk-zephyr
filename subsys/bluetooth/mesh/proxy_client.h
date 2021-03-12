#ifndef BT_MESH_PROXY_CLI_H__
#define BT_MESH_PROXY_CLI_H__

#include <bluetooth/bluetooth.h>
#include <net/buf.h>

#ifdef __cplusplus
extern "C" {
#endif

struct node_id_lookup {
	uint8_t addr;
	uint8_t net_idx;
};

void bt_mesh_proxy_client_process(const bt_addr_le_t *addr, int8_t rssi,
				  struct net_buf_simple *buf);

int bt_mesh_proxy_client_data_send(const void *data, uint16_t length);

int bt_mesh_proxy_client_init(void);

void bt_mesh_proxy_client_subnet_listen_set(uint16_t netidx);

bool bt_mesh_proxy_cli_relay(struct net_buf_simple *buf, uint16_t dst);

void bt_mesh_proxy_cli_node_id_ctx_set(struct node_id_lookup *ctx);

void bt_mesh_proxy_cli_adv_set(bool onoff);
bool bt_mesh_proxy_cli_is_adv_set(void);

#ifdef __cplusplus
}
#endif

#endif /* BT_MESH_PROXY_CLI_H__ */