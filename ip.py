from iputils import *
import struct

class IP:
    def __init__(self, enlace):
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.identification = 0 

    def ip_para_int(self, ip_str):
        partes = list(map(int, ip_str.split('.')))
        return (partes[0] << 24) | (partes[1] << 16) | (partes[2] << 8) | partes[3]

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
            src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        
        if dst_addr == self.meu_endereco:
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            next_hop = self._next_hop(dst_addr)

            if ttl <= 1:
                self.enviar_icmp_ttl_expirado(datagrama, src_addr)
                return
            
            ttl_novo = ttl - 1
            version_ihl = 0x45
            dscp_ecn = (dscp << 2) | ecn
            total_length = 20 + len(payload)
            flags_frag = (flags << 13) | frag_offset
            checksum = 0

            src_bytes = str2addr(src_addr)
            dst_bytes = str2addr(dst_addr)

            header_sem_checksum = struct.pack('!BBHHHBBH4s4s',
                version_ihl, dscp_ecn, total_length, identification,
                flags_frag, ttl_novo, proto, checksum, src_bytes, dst_bytes
            )

            checksum_calculado = calc_checksum(header_sem_checksum)

            header_completo = struct.pack('!BBHHHBBH4s4s',
                version_ihl, dscp_ecn, total_length, identification,
                flags_frag, ttl_novo, proto, checksum_calculado, src_bytes, dst_bytes
            )

            datagrama_modificado = header_completo + payload

            self.enlace.enviar(datagrama_modificado, next_hop)


    def enviar_icmp_ttl_expirado(self, datagrama_original, endereco_origem):
        tipo_icmp = 11
        codigo_icmp = 0
        checksum_icmp = 0
        campo_unused = 0

        icmp_payload = datagrama_original[:28]

        header_icmp = struct.pack('!BBHI', tipo_icmp, codigo_icmp, checksum_icmp, campo_unused)
        pacote_icmp = header_icmp + icmp_payload

        checksum_calculado = calc_checksum(pacote_icmp)

        header_icmp = struct.pack('!BBHI', tipo_icmp, codigo_icmp, checksum_calculado, campo_unused)
        pacote_icmp = header_icmp + icmp_payload

        cabecalho_ip_icmp = self.cabecalho_ip(
            src=self.meu_endereco,
            dst=endereco_origem,
            proto=IPPROTO_ICMP,
            tam_payload=len(pacote_icmp)
        )

        datagrama_icmp = cabecalho_ip_icmp + pacote_icmp

        next_hop = self._next_hop(endereco_origem)
        if next_hop:
            self.enlace.enviar(datagrama_icmp, next_hop)


    def cabecalho_ip(self, src, dst, proto, tam_payload, ttl=64):
        version_ihl = 0x45
        dscp_ecn = 0
        total_length = 20 + tam_payload
        identification = self.identification
        flags_frag_offset = 0
        checksum = 0
        src_bytes = str2addr(src)
        dst_bytes = str2addr(dst)

        hdr = struct.pack('!BBHHHBBH4s4s', version_ihl, dscp_ecn, total_length, identification, flags_frag_offset, ttl, proto, checksum, src_bytes, dst_bytes)

        checksum = calc_checksum(hdr)

        hdr = struct.pack('!BBHHHBBH4s4s', version_ihl, dscp_ecn, total_length, identification, flags_frag_offset, ttl, proto, checksum, src_bytes, dst_bytes)

        return hdr



    def _next_hop(self, dest_addr):
        dest_int = self.ip_para_int(dest_addr)
        melhor_prefixo = -1
        melhor_next_hop = None

        for rede_int, mascara, prefixo, next_hop in self.tabela_encaminhamento:
            if (dest_int & mascara) == (rede_int & mascara):
                if prefixo > melhor_prefixo:
                    melhor_prefixo = prefixo
                    melhor_next_hop = next_hop

        return melhor_next_hop

    def definir_endereco_host(self, meu_endereco):
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        self.tabela_encaminhamento = []
        for cidr, next_hop in tabela:
            rede_str, prefixo_str = cidr.split('/')
            rede_int = self.ip_para_int(rede_str)
            prefixo = int(prefixo_str)
            mascara = (0xFFFFFFFF << (32 - prefixo)) & 0xFFFFFFFF
            self.tabela_encaminhamento.append((rede_int, mascara, prefixo, next_hop))

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        next_hop = self._next_hop(dest_addr)

        version_ihl = 0x45
        dscp_ecn = 0
        total_length = 20 + len(segmento)
        identification = 0
        flags_frag_offset = 0 
        ttl = 64
        proto = IPPROTO_TCP
        checksum = 0
        src = str2addr(self.meu_endereco)
        dst = str2addr(dest_addr)

        header = struct.pack('!BBHHHBBH4s4s', version_ihl, dscp_ecn, total_length, identification, flags_frag_offset, ttl, proto, checksum, src, dst)

        checksum = calc_checksum(header)

        header = struct.pack('!BBHHHBBH4s4s', version_ihl, dscp_ecn, total_length, identification, flags_frag_offset, ttl, proto, checksum, src, dst)

        datagrama = header + segmento
        self.enlace.enviar(datagrama, next_hop)

