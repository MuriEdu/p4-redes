import traceback

# Constantes do protocolo SLIP (RFC 1055)
END = b'\xc0'
ESC = b'\xdb'
ESC_END = b'\xdc'
ESC_ESC = b'\xdd'


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
        self.callback = None
        self.buffer = b''

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, datagrama):
        """
        Envia um datagrama pela linha serial, aplicando o enquadramento
        e o byte stuffing do protocolo SLIP.
        
        Args:
            datagrama: Um objeto bytes com o datagrama a ser enviado.
        """
        # Passo 2: Aplicar byte stuffing. A ordem é importante.
        datagrama_escapado = datagrama.replace(ESC, ESC + ESC_ESC)
        datagrama_escapado = datagrama_escapado.replace(END, ESC + ESC_END)
        
        # Passo 1: Enquadrar o datagrama com o byte END no início e no fim.
        quadro = END + datagrama_escapado + END
        
        self.linha_serial.enviar(quadro)

    def __raw_recv(self, dados):
        """
        Processa os bytes brutos recebidos da linha serial.
        
        Monta os quadros, desfaz o byte stuffing e chama o callback
        com cada datagrama completo. Trata quadros quebrados e múltiplos
        quadros em uma única recepção.
        
        Args:
            dados: Bytes recebidos da linha serial.
        """
        if not self.callback:
            return

        self.buffer += dados
        
        # Divide os dados recebidos em quadros usando o delimitador END.
        quadros = self.buffer.split(END)
        
        # O último elemento pode ser um quadro incompleto. Guarda ele de volta no buffer.
        self.buffer = quadros[-1]
        
        quadros_completos = quadros[:-1]
        
        for quadro_bruto in quadros_completos:
            # Passo 3: Ignorar quadros vazios.
            if not quadro_bruto:
                continue

            try:
                # Passo 4: Desfazer o byte stuffing para obter o datagrama original.
                datagrama = quadro_bruto.replace(ESC + ESC_END, END)
                datagrama = datagrama.replace(ESC + ESC_ESC, ESC)
                
                # Entrega o datagrama para a camada superior.
                self.callback(datagrama)

            except:
                # Passo 5: Em caso de erro, imprime o traceback mas continua.
                print("ERRO: Ocorreu uma exceção na camada superior.")
                traceback.print_exc()