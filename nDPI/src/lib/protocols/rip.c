#include "ndpi_utils.h"
#include "ndpi_protocols.h"
#ifdef NDPI_PROTOCOL_RIP
void ndpi_search_rip(struct ndpi_detection_module_struct *ndpi_struct,
			    struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int8_t payload_command ;

  if (packet->payload_packet_len < 1)
	return;
  payload_command = packet->payload[0] & 0xff;

  /* Check whether this is an rip flow */
  if(
  	(packet->payload_packet_len <= 512)
     && (((packet->payload[1] & 0xFF) == 0x01) || ((packet->payload[1] & 0xFF) == 0x02))
     && (get_u_int16_t(packet->payload, 2)==htons(0x0000))
     && (get_u_int16_t(packet->payload, 6)==htons(0x0000))
     && (( (payload_command < 6)&&(payload_command>1))
     ) ){
    NDPI_LOG(NDPI_PROTOCOL_RIP, ndpi_struct, NDPI_LOG_DEBUG, "Found rip.\n");
    ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_RIP, NDPI_REAL_PROTOCOL);	
  } else {
    NDPI_LOG(NDPI_PROTOCOL_RIP, ndpi_struct, NDPI_LOG_DEBUG, "exclude rip.\n");
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_RIP);
  }
}
#endif


