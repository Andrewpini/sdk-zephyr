
void bt_mesh_proxy_client_process(const bt_addr_le_t *addr, int8_t rssi,
				  struct net_buf_simple *buf);

int bt_mesh_proxy_client_data_send(const void *data, uint16_t length);

int bt_mesh_proxy_client_init(void);

void bt_mesh_proxy_client_subnet_listen_set(uint16_t netidx);

bool bt_mesh_proxy_cli_relay(struct net_buf_simple *buf, uint16_t dst);