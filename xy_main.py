import base64
import binascii

from xhs_aes import XHS_AES
from xhs_md5 import XHS_MD5



class Shield:

    def __init__(self,versioncode,platform="ios",md5_k=0):
        """
        :param device_key: 小红书返回的x-ter-str
        :param device_id: 设备id
        :param content: 加密的内容
        """
        if platform == 'ios':
            self.__app_id = "ecfaaf02"
            self.flag = "02"
        if platform == "android":
            self.__app_id = "ecfaaf01"
            self.flag = "01"
        self.version_build = versioncode

    @staticmethod
    def strT0Hexstr(str):
        return binascii.hexlify(str.encode()).decode('utf-8')

    def get_oldsign(self,path='', params='', xy_common_params='', xy_platform_info='', data='', content='',
                main_hmac='', device_id=''):
        xhs = XHS_AES(xy_ter_str=main_hmac,deviceid=device_id)
        key = bytearray(xhs.key_hash)
        content = bytearray(content, encoding='utf-8') or bytearray(
            ''.join([path, params, xy_common_params, xy_platform_info, data]), encoding='utf-8')
        #hmac部分计算
        key_len = len(key)
        IPADKey = [0 for i in range(key_len)]
        for i in range(64):
            IPADKey[i] = key[i] ^ 0x36
        xhs1 = XHS_MD5()
        xhs1.md5Update(IPADKey, len(IPADKey))
        content = list(content)
        xhs1.md5Update(content,len(content))
        bytes1 = xhs1.md5Final()

        OPADKey = [0 for i in range(key_len)]
        for i in range(64):
            OPADKey[i] = key[i] ^ 0x5C
        xhs2 = XHS_MD5()
        xhs2.md5Update(OPADKey, len(IPADKey))
        res = xhs2.md5Final(bytes1)
        return res

    def getSign(self, path='', params='', xy_common_params='', xy_platform_info='', data='', content='',
                 main_hmac='', device_id=''):
        """
        生成签名  根据main_hmac device_id解密出一个key。
        """
        _res = self.get_oldsign(path=path, params=params, xy_common_params=xy_common_params,
                           xy_platform_info=xy_platform_info, data=data,
                           content=content, main_hmac=main_hmac, device_id=device_id)
        _res = bytearray(_res).hex()
        print(_res)
        newsign = self.calc_shield(device_id=device_id, oldsign=_res)
        return newsign

    def init_table(self):
        a1 = [0 for i in range(0x102)]
        a2 = 13
        a3 = [0x73, 0x74, 0x64, 0x3a, 0x3a, 0x61, 0x62, 0x6f, 0x72, 0x74, 0x28, 0x29, 0x3b]
        a1[0] = 0
        a1[1] = 0
        v11 = 0
        v7 = 0
        for i in range(256):
            a1[i + 2] = i
        for j in range(0, 256, 4):
            v15 = a1[j + 2]
            v8 = (a3[v11] + v15 + v7) & 0xff
            v12 = v11 + 1
            if v12 == a2:
                v12 = 0
            a1[j + 2] = a1[v8 + 2]
            a1[v8 + 2] = v15

            v16 = a1[j + 3]
            v9 = (a3[v12] + v16 + v8) & 0xff
            v13 = v12 + 1
            if v13 == a2:
                v13 = 0
            a1[j + 3] = a1[v9 + 2]
            a1[v9 + 2] = v16

            v17 = a1[j + 4]
            v10 = (a3[v13] + v17 + v9) & 0xff
            v14 = v13 + 1
            if v14 == a2:
                v14 = 0
            a1[j + 4] = a1[v10 + 2]
            a1[v10 + 2] = v17

            v18 = a1[j + 5]
            v7 = (a3[v14] + v18 + v10) & 0xff
            v11 = v14 + 1
            if v11 == a2:
                v11 = 0
            a1[j + 5] = a1[v7 + 2]
            a1[2 + v7] = v18
        return a1

    def init_base64_table(self, input_byte):
        input_len = len(input_byte)
        output_byte = [0 for i in range(input_len)]
        a1 = self.init_table()
        a2 = 0x53
        a3 = input_byte
        a4 = output_byte
        v51 = a1[0]
        v43 = a1[1]
        v59 = a1[2:]
        count = 0
        i = a2 >> 3
        while i > 0:
            v52 = (v51 + 1) & 0xff
            v28 = v59[v52]
            v44 = (v28 + v43) & 0xff
            v13 = v59[v44]
            v59[v52] = v13
            v59[v44] = v28
            a4[count] = (v59[(v28 + v13) & 0xff] ^ a3[count])
            v53 = (v52 + 1) & 0xff
            v29 = v59[v53]
            v45 = (v29 + v44) & 0xff
            v14 = v59[v45]
            v59[v53] = v14
            v59[v45] = v29
            a4[count + 1] = (v59[(v29 + v14) & 0xff] ^ a3[count + 1])
            v54 = (v53 + 1) & 0xff
            v30 = v59[v54]
            v46 = (v30 + v45) & 0xff
            v15 = v59[v46]
            v59[v54] = v15
            v59[v46] = v30
            a4[count + 2] = (v59[(v30 + v15) & 0xff] ^ a3[count + 2])
            v55 = (v54 + 1) & 0xff
            v31 = v59[v55]
            v47 = (v31 + v46) & 0xff
            v16 = v59[v47]
            v59[v55] = v16
            v59[v47] = v31
            a4[count + 3] = (v59[(v31 + v16) & 0xff] ^ a3[count + 3])
            v56 = (v55 + 1) & 0xff
            v32 = v59[v56]
            v48 = (v32 + v47) & 0xff
            v17 = v59[v48]
            v59[v56] = v17
            v59[v48] = v32
            a4[count + 4] = (v59[(v32 + v17) & 0xff] ^ a3[count + 4])
            v57 = (v56 + 1) & 0xff
            v33 = v59[v57]
            v49 = (v33 + v48) & 0xff
            v18 = v59[v49]
            v59[v57] = v18
            v59[v49] = v33
            a4[count + 5] = (v59[(v33 + v18) & 0xff] ^ a3[count + 5])
            v58 = (v57 + 1) & 0xff
            v34 = v59[v58]
            v50 = (v34 + v49) & 0xff
            v19 = v59[v50]
            v59[v58] = v19
            v59[v50] = v34
            a4[count + 6] = (v59[(v34 + v19) & 0xff] ^ a3[count + 6])
            v51 = (v58 + 1) & 0xff
            v35 = v59[v51]
            v43 = (v35 + v50) & 0xff
            v20 = v59[v43]
            v59[v51] = v20
            v59[v43] = v35
            a4[count + 7] = (v59[(v35 + v20) & 0xff] ^ a3[count + 7])
            count += 8
            i -= 1
        v6 = a2 & 7
        if (v6 != 0):
            while v6 > 0:
                v51 = (v51 + 1) & 0xff
                v36 = v59[v51]
                v43 = (v36 + v43) & 0xff
                v21 = v59[v43]
                v59[v51] = v21
                v59[v43] = v36
                a4[count] = (v59[(v36 + v21) & 0xff] ^ a3[count])
                v7 = v6 - 1
                if (v7 == 0):
                    break
                v51 = (v51 + 1) & 0xff
                v37 = v59[v51]
                v43 = (v37 + v43) & 0xff
                v22 = v59[v43]
                v59[v51] = v22
                v59[v43] = v37
                a4[count + 1] = (v59[(v37 + v22) & 0xff] ^ a3[count + 1])
                v8 = v7 - 1
                if (v8 == 0):
                    break
                v51 = (v51 + 1) & 0xff
                v37 = v59[v51]
                v43 = (v37 + v43) & 0xff
                v22 = v59[v43]
                v59[v51] = v22
                v59[v43] = v37
                a4[count + 2] = (v59[(v37 + v22) & 0xff] ^ a3[count + 2])
                v8 = v8 - 1
                if (v8 == 0):
                    break
                v51 = (v51 + 1) & 0xff
                v37 = v59[v51]
                v43 = (v37 + v43) & 0xff
                v22 = v59[v43]
                v59[v51] = v22
                v59[v43] = v37
                a4[count + 3] = (v59[(v37 + v22) & 0xff] ^ a3[count + 3])
                v8 = v8 - 1
                if (v8 == 0):
                    break
                v51 = (v51 + 1) & 0xff
                v37 = v59[v51]
                v43 = (v37 + v43) & 0xff
                v22 = v59[v43]
                v59[v51] = v22
                v59[v43] = v37
                a4[count + 4] = (v59[(v37 + v22) & 0xff] ^ a3[count + 4])
                v8 = v8 - 1
                if (v8 == 0):
                    break
                v51 = (v51 + 1) & 0xff
                v37 = v59[v51]
                v43 = (v37 + v43) & 0xff
                v22 = v59[v43]
                v59[v51] = v22
                v59[v43] = v37
                a4[count + 5] = (v59[(v37 + v22) & 0xff] ^ a3[count + 5])
                v8 = v8 - 1
                if (v8 == 0):
                    break
                v51 = (v51 + 1) & 0xff
                v37 = v59[v51]
                v43 = (v37 + v43) & 0xff
                v22 = v59[v43]
                v59[v51] = v22
                v59[v43] = v37
                a4[count + 6] = (v59[(v37 + v22) & 0xff] ^ a3[count + 6])
                v6 = v8 - 1
        return output_byte

    def shield_init(self, device_id, oldsign):
        "version长度7 device_id长度24 旧shield长度10"
        appid_hex_str = self.__app_id.lower()
        appversion_hex_str = self.strT0Hexstr(self.version_build)
        deviceid_hex_str = self.strT0Hexstr(device_id)
        oldshield_hex_str = oldsign
        calc_str = f"000000{self.flag}{appid_hex_str}00000002000000070000002400000010{appversion_hex_str}{deviceid_hex_str}{oldshield_hex_str}"
        print(calc_str)
        b_res = self.init_base64_table(bytes.fromhex(calc_str))
        return b_res

    def calc_shield(self, device_id, oldsign):
        output2 = [0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 83, 0, 0, 0, 83]
        output1 = self.shield_init(device_id, oldsign)
        b64_encode_str = output2 + output1
        _res = base64.b64encode(bytearray(b64_encode_str))
        return "XY" + _res.decode("utf-8")

shield = Shield(versioncode="7200370")
zz = shield.getSign(path="/api/sns/v1/system_service/check_code",params="code=147147&phone=15270065469&zone=86",
           device_id="C803DBA8-13A0-4B22-8FB2-B18A298AE2AA",xy_common_params="app_id=ECFAAF02&build=7200370&deviceId=C803DBA8-13A0-4B22-8FB2-B18A298AE2AA&device_fingerprint=20180919204408e9d9645bd8bc29c430aeb399145525fc01a5fc5ff3bf7585&fid=1639361924-0-0-6e8e5b4ec5fe4d1a01ba41b25a04edc7&identifier_flag=1&lang=zh-Hans&launch_id=661745425&platform=iOS&project_id=ECFAAF&sid=session.1639643018619800674202&t=1640052914&teenager=0&tz=Asia/Shanghai&uis=light&version=7.20",
           xy_platform_info="platform=iOS&version=7.20&build=7200370&deviceId=C803DBA8-13A0-4B22-8FB2-B18A298AE2AA&bundle=com.xingin.discover",
           main_hmac="Nl4PQ+hRr0vv4UQtkQJ5m8ALtCVvGlSTB1mSd9XGddEt5aP3dnB7DKI4Q1wuWtWhOJVXrqNTS0pkqw9Uf4uDxNp5l/IKGqihjYesf5fkD3HGVBGj+zGgApdkQe77moEE")
print(zz)

