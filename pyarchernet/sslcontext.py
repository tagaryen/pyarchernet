

class SSLContext():
    is_client_mode: bool
    verify_peer: bool
    ca: str
    crt: str
    key: str
    en_crt: str
    en_key: str
    matched_hostname: str
    named_curves: str

    def __init__(self, is_client_mode=True):
        self.is_client_mode = is_client_mode
        self.verify_peer = True


    @property
    def is_client_mode(self) -> bool:
        '''是否为客户端模式
        '''
        return self.is_client_mode
    
    @property
    def verify_peer(self) -> bool:
        '''是否为客户端模式
        '''
        return self.verify_peer

    @property
    def ca(self) -> str:
        '''ca证书内容
        '''
        return self.ca
    
    @property
    def crt(self)->str:
        '''证书内容
        '''
        return self.crt
    
    @property
    def key(self)->str:
        '''私钥内容
        '''
        return self.key
    
    @property
    def en_crt(self)->str:
        '''加密证书内容,用于gmssl
        '''
        return self.en_crt
    
    @property
    def en_key(self)->str:
        '''加密私钥内容,用于gmssl
        '''
        return self.en_key
    
    @property
    def matched_hostname(self)->str:
        '''证书校验时，证书中的域名，客户端模式有效
        '''
        return self.matched_hostname
    
    @property
    def named_curves(self)->str:
        '''ecc证书使用的椭圆曲线名称
        '''
        return self.named_curves