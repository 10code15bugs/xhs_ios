

def F(x,y,z):
    return (x & y) | ((~x) & z)

def G(x,y,z):
    return (x & z) | (y & (~z))

def H(x,y,z):
    return x ^ y ^ z

def I(x,y,z):
    return y ^ (x | (~z))

def ROTATE_LEFT(value, offset):
    value &= 0xFFFFFFFF
    temp = value >> offset
    mas = 0
    for i in range(offset):
        mas += pow(2,i)
    return temp | (value & mas) << 32 - offset

def FF(a, b, c, d, x, s, ac):
    a = a + F((b), (c), (d)) + (x) + (ac)
    a = ROTATE_LEFT(a,s)
    a = a + b
    return a  # must assign this to a


def GG(a, b, c, d, x, s, ac):
    a = a + G((b), (c), (d)) + (x) + (ac)
    a = ROTATE_LEFT((a), (s))
    a = a + b
    return a  # must assign this to a


def HH(a, b, c, d, x, s, ac):
    a = a + H((b), (c), (d)) + (x) + (ac)
    a = ROTATE_LEFT((a), (s))
    a = a + b
    return a  # must assign this to a


def II(a, b, c, d, x, s, ac):
    a = a + I((b), (c), (d)) + (x) + (ac)
    a = ROTATE_LEFT((a), (s))
    a = a + b
    return a  # must assign this to a

def b2iu(b):
    if b<0:
        return b & 0x7F + 128
    else:
        return b

def BIC(value, mas):
    value &= 0xFFFFFFFF
    return value & ~mas

class XHS_MD5:

    PADDING = [-128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0]

    def __init__(self):
        self.count = [0,0]
        self.state = [0, 0, 0, 0]


        self.state[0] = 0x10325476
        self.state[1] = 0x98badcfe
        self.state[2] = 0xefcdab89
        self.state[3] = 0x67452301

        self.buffer = [0 for i in range(64)]
        self.digest = [0 for i in range(16)]

    def md5Memcpy(self,output,input,outops,inops,len):

        output[outops:outops+len] = input[inops:inops+len]

    def md5Update(self,input, inputLen):
        block = [0 for i in range(64)]
        index = int(self.count[0] >> 3) & 0x3F
        self.count[0] = self.count[0] + (inputLen << 3)
        if self.count[0] < (inputLen << 3):
            self.count[1] += 1
        self.count[1] += (inputLen >> 29)
        partLen = 64 - index
        if inputLen >= partLen:
            self.md5Memcpy(self.buffer,input,index,0,partLen)
            # self.buffer = self.buffer[:index] + input[:partLen]
            self.md5Transform(self.buffer)
            i = partLen
            while i+63 < inputLen:
                self.md5Memcpy(block, input, 0 ,i ,i+64)
                self.md5Transform(block)
                i = i + 64
            index = 0
        else:
            i = 0
        self.md5Memcpy(self.buffer, input, index, i, inputLen-i)

    # def md5Update(self, input, inputLen=1):
    #     inputLen = len(input)
    #     index = int(self.count >> 3) & 0x3F
    #     self.count = self.count + (inputLen << 3)  # update number of bits
    #     partLen = XHS_MD5.block_size - index
    #
    #     # apply compression function to as many blocks as we have
    #     if inputLen >= partLen:
    #         self.buffer = self.buffer[:index] + input[:partLen]
    #         self.state = self.md5Transform(self.state, self.buffer)
    #         i = partLen
    #         while i + 63 < inputLen:
    #             self.state = self.md5Transform(self.state, input[i:i + XHS_MD5.block_size])
    #             i = i + XHS_MD5.block_size
    #         index = 0
    #     else:
    #         i = 0
    #
    #     # buffer remaining output
    #     self.buffer = self.buffer[:index] + input[i:inputLen]


    def md5Final(self,data=None):
        bits = [0 for i in range(8)]
        self.Encode(bits,self.count,8)
        if data != None:
            temp = [0 for i in range(64)]
            temp[0:len(data)] = data[0:len(data)]
            temp[len(data)] = 0x80
            temp[56] = 0x80
            temp[57] = 2
            self.md5Update(temp,64)
        else:
            index = int(self.count[0] >>  3) & 0x3f
            if index < 56:
                padLen = 56 - index
            else:
                padLen = 120 - index
            self.md5Update(self.PADDING, padLen)
        self.md5Update(bits,8)
        self.Encode(self.digest, self.state, 16)
        return self.digest


    def md5Transform(self,block):
        a = self.state[0]
        b = self.state[1]
        c = self.state[2]
        d = self.state[3]
        x = [0 for i in range(16)]
        self.Decode(x, block, 64)
        # round1
        a = FF(a, b, c, d, x[0], 26, 0xd76aa478)
        d = FF(d, a, b, c, x[1], 19, 0xe8c7b756)
        c = FF(c, d, a, b, x[2], 15, 0x242070db)
        b = FF(b, c, d, a, x[3], 11, 0xc1bdceee)
        a = FF(a, b, c, d, x[4], 25, 0xf57c0faf)
        d = FF(d, a, b, c, x[5], 20, 0x4787c62a)
        c = FF(c, d, a, b, x[6], 15, 0xa8304613)
        b = FF(b, c, d, a, x[7], 12, 0xfd469501)
        a = FF(a, b, c, d, x[8], 25, 0x698098d8)
        d = FF(d, a, b, c, x[9], 20, 0x8b44f7af)
        c = FF(c, d, a, b, x[10], 16, 0xffff5bb1)
        b = FF(b, c, d, a, x[11], 10, 0x895cd7be)
        a = FF(a, b, c, d, x[12], 25, 0x6b901122)
        d = FF(d, a, b, c, x[13], 19, 0xfd987193)
        c = FF(c, d, a, b, x[14], 15, 0xa679438e)
        b = FF(b, c, d, a, x[15], 10, 0x49b40821)

        # round2
        a = GG(a, b, c, d, x[1], 27, BIC(0xf61e2562, 0xFF00FF))
        d = GG(d, a, b, c, x[6], 23, 0xc040b340)
        c = GG(c, d, a, b, x[11], 18, 0x265e5a51)
        b = GG(b, c, d, a, x[0], 12, 0xe9b6c7aa & 0xFF0011FF)
        a = GG(a, b, c, d, x[5], 27, 0xd62f105d)
        d = GG(d, a, b, c, x[10], 23, 0x2441453)
        c = GG(c, d, a, b, x[15], 18, 0xd8a1e681)
        b = GG(b, c, d, a, x[4], 12, 0xe7d3fbc8)
        a = GG(a, b, c, d, x[9], 27, 0x21e1cde6)
        d = GG(d, a, b, c, x[14], 23, 0xc33707d6)
        c = GG(c, d, a, b, x[3], 18, 0xf4d50d87)
        b = GG(b, c, d, a, x[8], 12, 0x455a14ed)
        a = GG(a, b, c, d, x[13], 27, 0xa9e3e905)
        d = GG(d, a, b, c, x[2], 23, 0xfcefa3f8 & 0xFF110011)
        c = GG(c, d, a, b, x[7], 18, 0x676f02d9)
        b = GG(b, c, d, a, x[12], 12, 0x8d2a4c8a)
        # round3
        a = HH(a, b, c, d, x[5], 28, 0xfffa3942)
        d = HH(d, a, b, c, x[8], 21, 0x8771f681)
        c = HH(c, d, a, b, x[11], 16, 0x6d9d6122)
        b = HH(b, c, d, a, x[14], 9, 0xfde5380c)
        a = HH(a, b, c, d, x[1], 28, 0xa4beea44)
        d = HH(d, a, b, c, x[4], 21, 0x4bdecfa9)
        c = HH(c, d, a, b, x[7], 16, 0xf6bb4b60)
        a = HH(a, b, c, d, x[13], 28, 0x289b7ec6)
        b = HH(b, c, d, a, x[10], 9, 0xbebfbc70)
        c = HH(c, d, a, b, x[3], 16, 0xd4ef3085)
        d = HH(d, a, b, c, x[0], 21, 0xeaa127fa)
        b = HH(b, c, d, a, x[6], 9, 0x4881d05)
        a = HH(a, b, c, d, x[9], 28, 0xd9d4d039)
        d = HH(d, a, b, c, x[12], 21, 0xe6db99e5)
        c = HH(c, d, a, b, x[15], 16, 0x1fa27cf8)
        b = HH(b, c, d, a, x[2], 9, 0xc4ac5665)

        # round4
        a = II(a, b, c, d, x[0], 26, 0xf4292244)
        d = II(d, a, b, c, x[7], 22, 0x432aff97)
        c = II(c, d, a, b, x[14], 17, 0xab9423a7)
        b = II(b, c, d, a, x[5], 11, 0xfc93a039)
        a = II(a, b, c, d, x[12], 26, 0x655b59c3)
        d = II(d, a, b, c, x[3], 22, 0x8f0ccc92)
        c = II(c, d, a, b, x[10], 17, 0xffeff47d)
        b = II(b, c, d, a, x[1], 11, 0x85845dd1)
        a = II(a, b, c, d, x[8], 26, 0x6fa87e4f)
        d = II(d, a, b, c, x[15], 22, 0xfe2ce6e0)
        c = II(c, d, a, b, x[6], 17, 0xa3014314)
        b = II(b, c, d, a, x[13], 11, 0x4e0811a1)
        a = II(a, b, c, d, x[4], 26, 0xf7537e82)
        d = II(d, a, b, c, x[11], 22, 0xbd3af235)
        c = II(c, d, a, b, x[2], 17, 0x2ad7d2bb)
        b = II(b, c, d, a, x[9], 11, 0xeb86d391)

        self.state[0] += a
        self.state[1] += b
        self.state[2] += c
        self.state[3] += d


    def Encode(self, output, input, len_input):
        j = 0
        i = 0
        while j < len_input:
            output[j] = (input[i] & 0xff)
            output[j + 1] = ((input[i] >> 8) & 0xff)
            output[j + 2] = ((input[i] >> 16) & 0xff)
            output[j + 3] = ((input[i] >> 24) & 0xff)
            i += 1
            j += 4

    def Decode(self, output, input, len_input):
        j = 0
        i = 0
        while j < len_input:
            output[i] = b2iu(input[j]) | (b2iu(input[j + 1]) << 8) | (b2iu(input[j + 2]) << 16) | (b2iu(input[j + 3]) << 24)
            i += 1
            j += 4



if __name__ == '__main__':
    xymd5 = XHS_MD5()
    strlen = "/api/sns/v1/note/feednote_id=611e3446000000002103e745&page=1&has_ads_tag=false&num=5&fetch_mode=1&source=explore&ads_track_id=fm_fwfm_ol_30day%4028y6fh5sgzc4a916hbx23fid=162925699210bf9c0d3447ec1a57edbfc9b9f44f9625&device_fingerprint=20210810140918508c2ccd6e986960ec8432e9c2edd16b01265a5749ac3489&device_fingerprint1=20210810140918508c2ccd6e986960ec8432e9c2edd16b01265a5749ac3489&launch_id=1629451556&tz=Asia%2FShanghai&channel=YingYongBao&versionName=7.6.0&deviceId=879246a0-b385-3400-b59d-76f63fa5baff&platform=android&sid=session.1629264087421090169948&identifier_flag=4&t=1629451595&project_id=ECFAAF&build=7060188&x_trace_page_current=explore_feed&lang=zh-Hans&app_id=ECFAAF01&uis=lightplatform=android&build=7060188&deviceId=879246a0-b385-3400-b59d-76f63fa5baff".encode()
    strl = list(strlen)
    xymd5.md5Update(input=strl,inputLen=len(strl))
    print(bytearray(xymd5.md5Final()).hex())



