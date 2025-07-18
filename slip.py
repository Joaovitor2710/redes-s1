import traceback


class CamadaEnlace:
    ignore_checksum = False

    def __init__(self, linhas_seriais):
        """
        Inicia uma camada de enlace com um ou mais enlaces, cada um conectado
        a uma linha serial distinta. O argumento linhas_seriais é um dicionário
        no formato {ip_outra_ponta: linha_serial}. O ip_outra_ponta é o IP do
        host ou roteador que se encontra na outra ponta do enlace, escrito como
        uma string no formato 'x.y.z.w'. A linha_serial é um objeto da classe
        PTY (vide camadafisica.py) ou de outra classe que implemente os métodos
        registrar_recebedor e enviar.
        """
        self.enlaces = {}
        self.callback = None
        # Constrói um Enlace para cada linha serial
        for ip_outra_ponta, linha_serial in linhas_seriais.items():
            enlace = Enlace(linha_serial)
            self.enlaces[ip_outra_ponta] = enlace
            enlace.registrar_recebedor(self._callback)

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de enlace
        """
        self.callback = callback

    def enviar(self, datagrama, next_hop):
        """
        Envia datagrama para next_hop, onde next_hop é um endereço IPv4
        fornecido como string (no formato x.y.z.w). A camada de enlace se
        responsabilizará por encontrar em qual enlace se encontra o next_hop.
        """
        # Encontra o Enlace capaz de alcançar next_hop e envia por ele
        self.enlaces[next_hop].enviar(datagrama)

    def _callback(self, datagrama):
        if self.callback:
            self.callback(datagrama)


class Enlace:
    def __init__(self, linha_serial):
        self.linha_serial = linha_serial
        self.linha_serial.registrar_recebedor(self.__raw_recv)
        self.buffer = bytearray()
        self.escapando = False

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, datagrama):
        ESCAPES = {
            0xC0: [0xDB, 0xDC],
            0xDB: [0xDB, 0xDD]
        }

        quadro = bytearray([0xC0]) 

        for byte in datagrama:
            quadro.extend(ESCAPES.get(byte, [byte]))

        quadro.append(0xC0) 
        self.linha_serial.enviar(bytes(quadro))


    def __raw_recv(self, dados):
        i = 0
        while i < len(dados):
            byte = dados[i]

            if byte == 0xC0:
                if self.buffer:
                    datagrama = bytes(self.buffer)
                    self.buffer.clear()
                    try:
                        self.callback(datagrama)
                    except Exception:
                        traceback.print_exc()
                self.escapando = False  
                i += 1
                continue

            if self.escapando:
                mapped = {0xDC: 0xC0, 0xDD: 0xDB}.get(byte)
                if mapped is not None:
                    self.buffer.append(mapped)
                else:
                    self.buffer.clear() 
                self.escapando = False
            elif byte == 0xDB:
                self.escapando = True
            else:
                self.buffer.append(byte)

            i += 1


