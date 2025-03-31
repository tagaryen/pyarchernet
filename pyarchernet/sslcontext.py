class SSLContext():
    __is_client_mode: bool
    __verify_peer: bool
    __ca: str
    __crt: str
    __key: str
    __en_crt: str
    __en_key: str
    __matched_hostname: str
    __named_curves: str

    def __init__(self, is_client_mode=True):
        self.__is_client_mode = is_client_mode
        self.__verify_peer = True
        self.__ca = None
        self.__crt = None
        self.__key = None
        self.__en_crt = None
        self.__en_key = None
        self.__matched_hostname = None
        self.__named_curves = None


    @property
    def is_client_mode(self) -> bool:
        '''是否为客户端模式
        '''
        return self.__is_client_mode
    
    @is_client_mode.setter
    def is_client_mode(self, is_client_mode):
        self.__is_client_mode = is_client_mode
    
    @property
    def verify_peer(self) -> bool:
        '''是否为客户端模式
        '''
        return self.__verify_peer

    @verify_peer.setter
    def verify_peer(self, verify_peer):
        self.__verify_peer = verify_peer

    @property
    def ca(self) -> str:
        '''ca证书内容
        '''
        return self.__ca
    
    @ca.setter
    def ca(self, ca):
        self.__ca = ca

    @property
    def crt(self)->str:
        '''证书内容
        '''
        return self.__crt
    
    @crt.setter
    def crt(self, crt):
        self.__crt = crt

    @property
    def key(self)->str:
        '''私钥内容
        '''
        return self.__key
    
    @key.setter
    def key(self, key):
        self.__key = key

    @property
    def en_crt(self)->str:
        '''加密证书内容,用于gmssl
        '''
        return self.__en_crt
    
    @en_crt.setter
    def en_crt(self, en_crt):
        self.__en_crt = en_crt

    @property
    def en_key(self)->str:
        '''加密私钥内容,用于gmssl
        '''
        return self.__en_key
    
    @en_key.setter
    def en_key(self, en_key):
        self.__en_key = en_key

    @property
    def matched_hostname(self)->str:
        '''证书校验时，证书中的域名，客户端模式有效
        '''
        return self.__matched_hostname
    
    @matched_hostname.setter
    def matched_hostname(self, matched_hostname):
        self.__matched_hostname = matched_hostname

    @property
    def named_curves(self)->str:
        '''ecc证书使用的椭圆曲线名称
        '''
        return self.__named_curves
    
    @named_curves.setter
    def named_curves(self, named_curves):
        self.__named_curves = named_curves