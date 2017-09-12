struct xt_ndpi_cb {
  u_int16_t protocol_detected ; 
  u_int16_t ndpi_proto;
}xt_ndpi_cb_t;

#define NDPI_CB(skb)		(*(struct xt_ndpi_cb*)&((skb)->cb))
#define NDPI_CB_APPID(skb)		((!!NDPI_CB(skb).protocol_detected) ? NDPI_CB(skb).ndpi_proto:0)

#define NDPI_CB_RECORD(skb,entry) 	NDPI_CB(skb).ndpi_proto = (u_int16_t)entry->ndpi_proto; \
					NDPI_CB(skb).protocol_detected = (u_int16_t)entry->protocol_detected;
