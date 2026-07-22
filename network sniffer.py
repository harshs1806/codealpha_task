import socket
import struct
import datetime

def mac_addr(bytes_addr):
    return ':'.join(f'{b:02x}' for b in bytes_addr)

def get_proto_name(n):
    return {1: "ICMP", 6: "TCP", 17: "UDP"}.get(n, f"PROTO_{n}")

def sniff():
    if not hasattr(socket, "PF_PACKET"):
        print("This code works on Linux only.")
        return

    try:
        conn = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        print("Packet capture started... Press Ctrl+C to stop.\n")

        while True:
            frame, _ = conn.recvfrom(65535)

            if len(frame) < 34:
                continue

            dst_mac, src_mac, eth_type = struct.unpack("!6s6sH", frame[:14])
            if eth_type != 0x0800:
                continue

            ip_header = frame[14:34]
            iph = struct.unpack("!BBHHHBBH4s4s", ip_header)

            ihl = (iph[0] & 0x0F) * 4
            protocol_num = iph[6]
            src_ip = socket.inet_ntoa(iph[8])
            dst_ip = socket.inet_ntoa(iph[9])
            protocol = get_proto_name(protocol_num)

            transport_start = 14 + ihl
            src_port = ""
            dst_port = ""
            payload = b""

            if protocol_num == 6 and len(frame) >= transport_start + 20:
                tcp_header = frame[transport_start:transport_start + 20]
                tcph = struct.unpack("!HHLLBBHHH", tcp_header)
                src_port = tcph[0]
                dst_port = tcph[1]
                data_offset = ((tcph[4] >> 4) * 4)
                payload = frame[transport_start + data_offset:]

            elif protocol_num == 17 and len(frame) >= transport_start + 8:
                udp_header = frame[transport_start:transport_start + 8]
                udph = struct.unpack("!HHHH", udp_header)
                src_port = udph[0]
                dst_port = udph[1]
                payload = frame[transport_start + 8:]

            elif protocol_num == 1:
                payload = frame[transport_start:]

            payload_text = payload[:50].decode("utf-8", errors="ignore").strip()
            if not payload_text:
                payload_text = str(payload[:20])

            print(
                f"[{datetime.datetime.now().strftime('%H:%M:%S')}] "
                f"IP {src_ip} -> {dst_ip} | "
                f"{protocol} {src_port} -> {dst_port} | "
                f"PAYLOAD: {payload_text}"
            )

    except PermissionError:
        print("Run the script with sudo/root privileges.")
    except KeyboardInterrupt:
        print("\nCapture stopped.")
    except OSError as e:
        print(f"Socket error: {e}")

if __name__ == "__main__":
    sniff()