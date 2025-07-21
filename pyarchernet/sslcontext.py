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
    __max_version: int
    __min_version: int

    def __init__(self, is_client_mode=True):
        if is_client_mode is None or not isinstance(is_client_mode, bool):
            raise ValueError("is_client_mode must be bool")
        self.__is_client_mode = is_client_mode
        self.__verify_peer = True
        self.__ca = None
        self.__crt = None
        self.__key = None
        self.__en_crt = None
        self.__en_key = None
        self.__matched_hostname = None
        self.__named_curves = None
        if is_client_mode:
            self.__max_version = 772
            self.__min_version = 769
        else:
            self.__max_version = 772
            self.__min_version = 769


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
    def verify_peer(self, verify_peer) -> bool:
        self.__verify_peer = verify_peer

    @property
    def ca(self) -> str:
        '''ca证书内容
        '''
        return self.__ca
    
    @ca.setter
    def ca(self, ca):
        if ca is not None and not isinstance(ca, str):
            raise ValueError("ca must be str")
        self.__ca = ca

    @property
    def crt(self)->str:
        '''证书内容
        '''
        return self.__crt
    
    @crt.setter
    def crt(self, crt):
        if crt is not None and not isinstance(crt, str):
            raise ValueError("crt must be str")
        self.__crt = crt

    @property
    def key(self)->str:
        '''私钥内容
        '''
        return self.__key
    
    @key.setter
    def key(self, key):
        if key is not None and not isinstance(key, str):
            raise ValueError("key must be str")
        self.__key = key

    @property
    def en_crt(self)->str:
        '''加密证书内容,用于gmssl
        '''
        return self.__en_crt
    
    @en_crt.setter
    def en_crt(self, en_crt):
        if en_crt is not None and not isinstance(en_crt, str):
            raise ValueError("en_crt must be str")
        self.__en_crt = en_crt

    @property
    def en_key(self)->str:
        '''加密私钥内容,用于gmssl
        '''
        return self.__en_key
    
    @en_key.setter
    def en_key(self, en_key):
        if en_key is not None and not isinstance(en_key, str):
            raise ValueError("en_key must be str")
        self.__en_key = en_key

    @property
    def max_version(self)->int:
        '''ssl 版本max
        '''
        return self.__max_version
    
    @max_version.setter
    def max_version(self, max_version: int):
        if max_version is not None and not isinstance(max_version, int):
            raise ValueError("max_version must be int")
        if max_version > 772:
            max_version = 722
        if max_version < 769:
            max_version = 769
        self.__max_version = max_version

    @property
    def min_version(self)->int:
        '''ssl 版本min
        '''
        return self.__min_version
    
    @min_version.setter
    def min_version(self, min_version: int):
        if min_version is not None and not isinstance(min_version, int):
            raise ValueError("min_version must be int")
        if min_version > 772:
            min_version = 722
        if min_version < 769:
            min_version = 769
        self.__min_version = min_version


    @property
    def matched_hostname(self)->str:
        '''证书校验时，证书中的域名，客户端模式有效
        '''
        return self.__matched_hostname
    
    @matched_hostname.setter
    def matched_hostname(self, matched_hostname):
        if matched_hostname is not None and not isinstance(matched_hostname, str):
            raise ValueError("matched_hostname must be str")
        self.__matched_hostname = matched_hostname

    @property
    def named_curves(self)->str:
        '''ecc证书使用的椭圆曲线名称
        '''
        return self.__named_curves
    
    @named_curves.setter
    def named_curves(self, named_curves):
        if named_curves is not None and not isinstance(named_curves, str):
            raise ValueError("named_curves must be str")
        self.__named_curves = named_curves