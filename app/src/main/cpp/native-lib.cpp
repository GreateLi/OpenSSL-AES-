#include <jni.h>
#include <string>

#include<android/log.h>
#include <cstring>
#include <cstdlib>
#include <openssl/aes.h>
#include <openssl/ossl_typ.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

#include <string>
#include <zlib.h>

#define TAG "native-lib" // 这个是自定义的LOG的标识
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG,TAG ,__VA_ARGS__) // 定义LOGD类型
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,TAG ,__VA_ARGS__) // 定义LOGI类型
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,TAG ,__VA_ARGS__) // 定义LOGW类型
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,TAG ,__VA_ARGS__) // 定义LOGE类型
#define LOGF(...) __android_log_print(ANDROID_LOG_FATAL,TAG ,__VA_ARGS__) // 定义LOGF类型

#define AES_BITS 128
#define MSG_LEN 1024
using namespace std;
#define SDK_VERSION "NDK_ASE_DEMO.0.1"

string Base64Encode(const char * input, int length, bool with_new_line)
{
    BIO * bmem = NULL;
    BIO * b64 = NULL;
    BUF_MEM * bptr = NULL;

    b64 = BIO_new(BIO_f_base64());
    if(!with_new_line) {
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    }
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    //这里的第二个参数很重要，必须赋值
    std::string result(bptr->data, bptr->length);
    BIO_free_all(b64);
    return result;
}

string Base64Decode(const char * input, int length, bool with_new_line)
{
    BIO * b64 = NULL;
    BIO * bmem = NULL;
    unsigned char * buffer = (unsigned char *)malloc(length);
    memset(buffer, 0, length);

    b64 = BIO_new(BIO_f_base64());
    if(!with_new_line) {
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    }
    bmem = BIO_new_mem_buf(input, length);
    bmem = BIO_push(b64, bmem);
    int ret = BIO_read(bmem, buffer, length);
    //这里的第二个参数很重要，必须赋值
    std::string result((char*)buffer, ret);

    BIO_free_all(bmem);

    return result;
}

int aes_encrypt(const unsigned char* in, const unsigned char* key, const unsigned char* out, int inLen)
{
    if (!in || !key || !out) return 0;
    unsigned char iv[AES_BLOCK_SIZE];//加密的初始化向量
    for (int i = 0; i<AES_BLOCK_SIZE; ++i)//iv一般设置为全0,可以设置其他，但是加密解密要一样就行
        iv[i] = 0;
    AES_KEY aes;
    if (AES_set_encrypt_key((unsigned char*)key, 128, &aes) < 0)
    {
        return 0;
    }
    int len = inLen;//这里的长度是char*in的长度，但是如果in中间包含'\0'字符的话

    //那么就只会加密前面'\0'前面的一段，所以，这个len可以作为参数传进来，记录in的长度

    //至于解密也是一个道理，光以'\0'来判断字符串长度，确有不妥，后面都是一个道理。
    AES_cbc_encrypt((unsigned char*)in, (unsigned char*)out, len, &aes, iv, AES_ENCRYPT);
    return 1;
}
 int aes_decrypt(const unsigned char* in, const unsigned char* key, const unsigned char* out, int inLen)
{
    if (!in || !key || !out) return 0;
    unsigned char iv[AES_BLOCK_SIZE];//加密的初始化向量
    for (int i = 0; i<AES_BLOCK_SIZE; ++i)//iv一般设置为全0,可以设置其他，但是加密解密要一样就行
        iv[i] = 0;
    AES_KEY aes;
    if (AES_set_decrypt_key((unsigned char*)key, 128, &aes) < 0)
    {
        return 0;
    }
    int len =inLen;
    AES_cbc_encrypt((unsigned char*)in, (unsigned char*)out, len, &aes, iv, AES_DECRYPT);
    return 1;
}

/*   Byte值转换为bytes字符串
*   @param src：Byte指针 srcLen:src长度 des:转换得到的bytes字符串
**/
 void Bytes2HexStr( unsigned char *src,int srcLen, unsigned char *des)
{
    unsigned char *res;
    int i=0;

    res = des;
    while(srcLen>0)
    {
        sprintf((char*)(res+i*2),"%02x",*(src+i));
        i++;
        srcLen--;
    }
}

/**
 * bytes字符串转换为Byte值
* @param String src Byte字符串，每个Byte之间没有分隔符
* @return byte[]
*/
 unsigned char * hexStr2Bytes(string src)
{
    char *strEnd;
    int m=0;
    int len = src.length()/2;
    unsigned char* ret = new unsigned char[len];

    for(int i =0;i<len;i++)
    {
        m = i*2;
        string subs = src.substr(m,2);
        ret[i] = strtol(subs.c_str(),&strEnd,16);
    }
    return ret;
}

int AESTest(string content)  //注意，如果是 to Bytes2HexStr 输入需要是 16倍数，如果用base 会自动 补全。
{
    string keyTemp= content;
    int keylen = keyTemp.length();
    unsigned char sourceStringTemp[MSG_LEN]={0};
    unsigned char dstStringTemp[MSG_LEN]={0};
    unsigned char paint[MSG_LEN]={0};
    memset((char*)sourceStringTemp, 0, MSG_LEN);
    memset((char*)dstStringTemp, 0, MSG_LEN);
    memcpy( sourceStringTemp, keyTemp.c_str(),keylen);
    memcpy( paint, keyTemp.c_str(),keylen);

    char key[AES_BLOCK_SIZE+1]={0};
    int i;

    time_t now;
    time(&now);
    memcpy(key,SDK_VERSION,AES_BLOCK_SIZE);
    LOGD( "aes_encrypt starttime: %ld  ",now);
    if (!aes_encrypt(sourceStringTemp, (const unsigned char*)key, dstStringTemp,keylen))
    {
        LOGD("encrypt error\n");
        return -1;
    }

    time_t end;
    time(&end);
    LOGD("aes_encrypt endtime: %ld  ",end);

    unsigned char deshx[MSG_LEN]={0};
    Bytes2HexStr(dstStringTemp,keylen,deshx);
   // string* hexStr = Byte2Hex(dstStringTemp,keylen);

    string result((char*)deshx);
    LOGD(" Encode Byte2Hex: %s  ",result.c_str());

    unsigned char * dehex = hexStr2Bytes(result);
    //    LOGD(" Encode hexStr2Bytes: %s  ",dehex);
//    string base64Str = Base64Encode((const char*)dstStringTemp,keylen,false);
//
//    LOGD(" Encode base64Str: %s  ",base64Str.c_str());
//    string baseEncodeStr = base64Str;
//    unsigned char DecodeStringTemp[MSG_LEN]={0};
//    int decodelen  = 1024;
//    //int retSucc = base64_decode(base64Str.c_str(),base64Str.length(),DecodeStringTemp,&decodelen);
//    string base64StrDec  =
//        Base64Decode(base64Str.c_str(),base64Str.length() , false);//  Base64Decode(baseEncodeStr.c_str(),baseEncodeStr.length(),false);
//    LOGD("Base64Decode base64StrDec: %s  ",(char*)DecodeStringTemp);
    //LOGD("Base64Decode base64StrDec: %s  ",base64StrDec.c_str());

    printf("enc %d:", strlen((char*)dstStringTemp));
    for (i = 0; dstStringTemp[i]; i += 1) {
        printf("%x", (unsigned char)dstStringTemp[i]);
    }
    memset((char*)sourceStringTemp, 0, MSG_LEN);
    if (!aes_decrypt((const unsigned char*)dehex, (const unsigned char*)key, sourceStringTemp,keylen))
    {
        LOGD("decrypt error\n");
        return -1;
    }
    printf("\n");
    int len = strlen((char*)sourceStringTemp);
    LOGD( "dec %d:", len);
    LOGD( "%s\n", sourceStringTemp);


    /*对比解密后与原数据是否一致*/
    if(!memcmp(paint, sourceStringTemp, keylen)) {
        LOGD("test success\n");
    } else {
        LOGD("test failed\n");
    }

    for (i = 0; sourceStringTemp[i]; i += 1) {
        LOGD( "%x", (unsigned char)sourceStringTemp[i]);
    }

    return 0;
}

std::string jstring2str(JNIEnv* env, jstring jstr)
{
    char*   rtn   =   NULL;
    jclass   clsstring   =   env->FindClass("java/lang/String");
    jstring   strencode   =   env->NewStringUTF("GB2312");
    jmethodID   mid   =   env->GetMethodID(clsstring,   "getBytes",   "(Ljava/lang/String;)[B");
    jbyteArray   barr=   (jbyteArray)env->CallObjectMethod(jstr,mid,strencode);
    jsize   alen   =   env->GetArrayLength(barr);
    jbyte*   ba   =   env->GetByteArrayElements(barr,JNI_FALSE);
    if(alen   >   0)
    {
        rtn   =   (char*)malloc(alen+1);
        memcpy(rtn,ba,alen);
        rtn[alen]=0;
    }
    env->ReleaseByteArrayElements(barr,ba,0);
    std::string stemp(rtn);
    free(rtn);
    return   stemp;
}
extern "C" JNIEXPORT jstring JNICALL
Java_aes_cn_com_aesdemo_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */,jstring content) {
    std::string hello = jstring2str(env,content);
    char AESString[1024] = {0};
    AESTest(hello);

    return env->NewStringUTF(hello.c_str());
}
