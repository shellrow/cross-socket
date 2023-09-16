use std::io;
use crate::packet::PacketInfo;

pub(crate) fn build_and_send_packet(_tx: &mut Box<dyn pnet::datalink::DataLinkSender>, _packet_frame: PacketInfo) -> io::Result<()> {
    // TODO Implement
    Ok(())
}
