#include <iostream>
#include <Windows.h>
#include <fstream>
#include <algorithm>
#include <sstream>
#include <string>
using namespace std;

#include "magic_constants.h"
#include "AES-128.h"
#include "lz4.h"

void Decrypt(std::byte* bytes, unsigned int size) {
	uint8_t* key1 = new uint8_t[0x10];
	uint8_t* key2 = new uint8_t[0x10];
	uint8_t* key3 = new uint8_t[0x10];

	memcpy(key1, bytes + 4, 0x10);
	memcpy(key2, bytes + 0x74, 0x10);
	memcpy(key3, bytes + 0x84, 0x10);

	//__int32 encryptedBlockSize = std::min({ 0x10 * ((size - 0x94) >> 7), 0x400 });
	unsigned __int32 encryptedBlockSize;

	if (0x10 * ((size - 0x94) >> 7) < 0x400)
		encryptedBlockSize = 0x10 * ((size - 0x94) >> 7);
	else
		encryptedBlockSize = 0x400;

	std::byte* encryptedBlock = new std::byte[encryptedBlockSize];
	memcpy(encryptedBlock, bytes + 0x94, encryptedBlockSize); // 不知道为什么C#这里会少读16字节

	for (int i = 0; i < sizeof(ConstKey) / sizeof(*ConstKey); i++)
		key2[i] ^= ConstKey[i];

    AESDecrypt(key1, (uint8_t*)ExpansionKey);
    AESDecrypt(key3, (uint8_t*)ExpansionKey);

	for (int i = 0; i < 0x10; i++)
		key1[i] ^= key3[i];

	memcpy(bytes + 0x84, key1, 0x10);

	unsigned __int64 seed1;
	memcpy(&seed1, key2, sizeof key2);
	unsigned __int64 seed2;
	memcpy(&seed2, key3, sizeof key3);
	unsigned __int64 seed = seed2 ^ seed1 ^ (seed1 + (unsigned int)size - 20);

	std::byte seedBytes[sizeof(seed)];

	for (int i = 0; i < sizeof(seed); i++)
	{
		seedBytes[i] = (std::byte)((seed >> (8 * i)) & 0xFF);
	}

	for (int i = 0; i < encryptedBlockSize; i++)
	{
		encryptedBlock[i] ^= (std::byte)((uint8_t)seedBytes[i % 8] ^ Key[i]);
	}
	memcpy(bytes + 0x94, encryptedBlock, encryptedBlockSize);

}

// From : https://stackoverflow.com/questions/21819782/writing-hex-to-a-file
std::string translate_hex_to_write_to_file(std::string hex) {
    std::basic_string<uint8_t> bytes;

    // Iterate over every pair of hex values in the input string (e.g. "18", "0f", ...)
    for (size_t i = 0; i < hex.length(); i += 2)
    {
        uint16_t byte;

        // Get current pair and store in nextbyte
        std::string nextbyte = hex.substr(i, 2);

        // Put the pair into an istringstream and stream it through std::hex for
        // conversion into an integer value.
        // This will calculate the byte value of your string-represented hex value.
        std::istringstream(nextbyte) >> std::hex >> byte;

        // As the stream above does not work with uint8 directly,
        // we have to cast it now.
        // As every pair can have a maximum value of "ff",
        // which is "11111111" (8 bits), we will not lose any information during this cast.
        // This line adds the current byte value to our final byte "array".
        bytes.push_back(static_cast<uint8_t>(byte));
    }

    // we are now generating a string obj from our bytes-"array"
    // this string object contains the non-human-readable binary byte values
    // therefore, simply reading it would yield a String like ".0n..:j..}p...?*8...3..x"
    // however, this is very useful to output it directly into a binary file like shown below
    std::string result(begin(bytes), end(bytes));

    return result;
}

struct StorageBlock {
    unsigned __int32 compressedSize = 0;
    unsigned __int32 uncompressedSize = 0;
    unsigned __int16 flags = 0;
};

struct Node
{
    unsigned __int64 offset = 0;
    unsigned __int64 size = 0;
    unsigned __int16 flags = 0;
    string path;
};

string ReadStringToNull(fstream &bytes) {
    //std::byte* m = bytes;
    unsigned int start_ptr = bytes.tellg();
    char* v3 = new char;
    int path_size = 0;
    for (int a = 0;; a++) {
        bytes.read(v3, 1);
        if ((int)*v3 == 0) {
            path_size++;
            break;
        }
        path_size++;
    }
    char* path_v1 = new char[path_size];
    bytes.clear();
    bytes.seekg(start_ptr);
    bytes.read(path_v1, path_size);
    string path = path_v1;
    return path;
}

void AlignStream(fstream& bytes, int alignment) {
    unsigned int pos = bytes.tellg();
    unsigned int a = bytes.tellg();
    unsigned int mod = pos % alignment;
    if (mod != 0)
    {
        bytes.clear();
        bytes.seekg(a + alignment - mod);
    }
}

int tranlate_to_normal_unity3d_file(string inpath, string outpath) {

    cout << "[Debug] 加密文件目录:" << inpath << endl;
    cout << "[Debug] 解密文件目录:" << outpath << endl;

    fstream mhy_unity3d_file;
    
    mhy_unity3d_file.open(inpath, ios::in | ios::binary);
    
    // ReadHeader
    unsigned char version[sizeof(__int32)];
    unsigned char bundleSize[sizeof(__int64)];
    unsigned char compressedBlocksInfoSize[sizeof(__int32)];
    unsigned char uncompressedBlocksInfoSize[sizeof(__int32)];
    unsigned char flag[sizeof(__int32)];

    string signature = ReadStringToNull(mhy_unity3d_file);

    mhy_unity3d_file.clear();
    mhy_unity3d_file.read(reinterpret_cast<char*>(version), sizeof(version));
    string unityVersion = ReadStringToNull(mhy_unity3d_file);
    string unityRevisions = ReadStringToNull(mhy_unity3d_file);
    mhy_unity3d_file.read(reinterpret_cast<char*>(bundleSize), sizeof(bundleSize));
    mhy_unity3d_file.read(reinterpret_cast<char*>(compressedBlocksInfoSize), sizeof(compressedBlocksInfoSize));
    mhy_unity3d_file.read(reinterpret_cast<char*>(uncompressedBlocksInfoSize), sizeof(uncompressedBlocksInfoSize));
    mhy_unity3d_file.read(reinterpret_cast<char*>(flag), sizeof(flag));
    AlignStream(mhy_unity3d_file, 0x10);

    // https://stackoverflow.com/questions/34780365/how-do-i-convert-an-unsigned-char-array-into-an-unsigned-long-long
    unsigned int bundleSize_unsigned_int;
    memcpy(&bundleSize_unsigned_int, bundleSize, sizeof bundleSize);
    bundleSize_unsigned_int = _byteswap_ulong(bundleSize_unsigned_int);

    unsigned int compressedBlocksInfoSize_unsigned_int;
    memcpy(&compressedBlocksInfoSize_unsigned_int, compressedBlocksInfoSize, sizeof compressedBlocksInfoSize);
	compressedBlocksInfoSize_unsigned_int = _byteswap_ulong(compressedBlocksInfoSize_unsigned_int);

    unsigned int uncompressedBlocksInfoSize_unsigned_int;
    memcpy(&uncompressedBlocksInfoSize_unsigned_int, uncompressedBlocksInfoSize, sizeof uncompressedBlocksInfoSize);
	uncompressedBlocksInfoSize_unsigned_int = _byteswap_ulong(uncompressedBlocksInfoSize_unsigned_int);

    unsigned int flag_unsigned_int;
    memcpy(&flag_unsigned_int, flag, sizeof flag);
    flag_unsigned_int = _byteswap_ulong(flag_unsigned_int);

    cout << "[Debug] compressedBlocksInfoSize: " << compressedBlocksInfoSize_unsigned_int << endl;
    cout << "[Debug] uncompressedBlocksInfoSize: " << uncompressedBlocksInfoSize_unsigned_int << endl;

    std::byte* blocksInfoBytes = new std::byte[compressedBlocksInfoSize_unsigned_int];
    std::byte* uncompressedBlocksInfo = new std::byte[uncompressedBlocksInfoSize_unsigned_int];
    mhy_unity3d_file.read(reinterpret_cast<char*>(blocksInfoBytes), compressedBlocksInfoSize_unsigned_int);

    //unsigned int blocksInfoBytes_D_size = 0;
    if ((flag_unsigned_int & 0x3F) == 0x5 && compressedBlocksInfoSize_unsigned_int > 0xFF) {
        Decrypt(blocksInfoBytes, compressedBlocksInfoSize_unsigned_int);
        blocksInfoBytes += 0x14;
        compressedBlocksInfoSize_unsigned_int -= 0x14;
    }

	long long v1 = compressedBlocksInfoSize_unsigned_int;
	long long v2 = uncompressedBlocksInfoSize_unsigned_int;

	LZ4_decompress_safe((char*)blocksInfoBytes, (char*)uncompressedBlocksInfo, compressedBlocksInfoSize_unsigned_int, uncompressedBlocksInfoSize_unsigned_int);

    // 我叼你妈的内存分配 FUCK (可能是内存覆盖导致堆损坏)
    // 为了重新打包不能释放内存
    // delete[] blocksInfoBytes;

    // ReadBlocksInfoAndDirectory

    char uncompressedDataHash[16];
    memcpy(uncompressedDataHash, uncompressedBlocksInfo, 16i64);
    uncompressedBlocksInfo += 16i64;

    unsigned int blocksInfoCount;
    memcpy(&blocksInfoCount, uncompressedBlocksInfo, 4i64);
    blocksInfoCount = (((blocksInfoCount << 16) | blocksInfoCount & 0xFF00) << 8) | ((HIWORD(blocksInfoCount) | blocksInfoCount & 0xFF0000) >> 8);

    cout << "[Debug] blocksInfoCount:" << blocksInfoCount << endl;

    StorageBlock* m_BlocksInfo = new StorageBlock[blocksInfoCount];

    uncompressedBlocksInfo = uncompressedBlocksInfo + 4;

    for (int i = 0; i < blocksInfoCount; i++) {
        // 大小端转换
        memcpy(&m_BlocksInfo[i].uncompressedSize, uncompressedBlocksInfo ,4i64);
        m_BlocksInfo[i].uncompressedSize = _byteswap_ulong(m_BlocksInfo[i].uncompressedSize);
        uncompressedBlocksInfo += 4i64;

        memcpy(&m_BlocksInfo[i].compressedSize, uncompressedBlocksInfo, 4i64);
        m_BlocksInfo[i].compressedSize = _byteswap_ulong(m_BlocksInfo[i].compressedSize);
        uncompressedBlocksInfo += 4i64;

        memcpy(&m_BlocksInfo[i].flags, uncompressedBlocksInfo, 2i64);
        m_BlocksInfo[i].flags = _byteswap_ushort(m_BlocksInfo[i].flags);
        uncompressedBlocksInfo += 2i64;
    }


    unsigned int nodesCount;
    if (blocksInfoCount) {
        memcpy(&nodesCount, uncompressedBlocksInfo, 4i64);
        uncompressedBlocksInfo += 4i64;
        nodesCount = (((nodesCount << 16) | nodesCount & 0xFF00) << 8) | ((HIWORD(nodesCount) | nodesCount & 0xFF0000) >> 8);
        cout << "[Debug] nodesCount:" << nodesCount << endl;
    }
    else
        return 0;

    Node* m_DirectoryInfo = new Node[nodesCount];

    unsigned int path_size = 0;
    char* v3 = new char;
    std::byte* uncompressedBlocksInfo_set;

    for (int i = 0; i < nodesCount; i++)
    {
        memcpy(&m_DirectoryInfo[i].offset, uncompressedBlocksInfo, 8i64);
        uncompressedBlocksInfo += 8i64;

        memcpy(&m_DirectoryInfo[i].size, uncompressedBlocksInfo, 8i64);
        uncompressedBlocksInfo += 8i64;

        memcpy(&m_DirectoryInfo[i].flags, uncompressedBlocksInfo, 4i64);
        m_DirectoryInfo[i].flags = _byteswap_ulong(m_DirectoryInfo[i].flags);
        uncompressedBlocksInfo += 4i64;

        uncompressedBlocksInfo_set = uncompressedBlocksInfo;

        // ReadStringToNull()
        for (int a = 0;; a++) {
            memcpy(v3, uncompressedBlocksInfo, 1i64);
            if ((int)*v3 == 0) {
                path_size++;
                uncompressedBlocksInfo++;
                break;
            }
            path_size++;
            uncompressedBlocksInfo++;
        }
        char* path_v1 = new char[path_size];
        strcpy_s(path_v1, path_size, (const char *)uncompressedBlocksInfo_set);
        m_DirectoryInfo[i].path = path_v1;
    }

    // CreateBlocksStream
    
    // 为了重新打包改为compressedSizeSum
    /*
    unsigned __int32 uncompressedSizeSum = 0;
    for (int i = 0; i < blocksInfoCount; i++) {
        uncompressedSizeSum += m_BlocksInfo[i].uncompressedSize;
    }

    std::byte* blocksStream = new std::byte[uncompressedSizeSum];
    */

    unsigned __int32 compressedSizeSum = 0;
    for (int i = 0; i < blocksInfoCount; i++) {
        compressedSizeSum += m_BlocksInfo[i].compressedSize;
    }

    std::byte* blocksStream = new std::byte[compressedSizeSum];
    std::byte* blocksStream_start_address = blocksStream;

    // ReadBlocks(DecryptBlocks)

    unsigned int compressedSize;
    std::byte* compressedBytes;

    for (int i = 0; i < blocksInfoCount; i++) {
        compressedSize = m_BlocksInfo[i].compressedSize;
        compressedBytes = new std::byte[compressedSize];
        mhy_unity3d_file.read(reinterpret_cast<char*>(compressedBytes), compressedSize);
        if ((m_BlocksInfo[i].flags & 0x3F) == 0x5 && compressedSize > 0xFF) {
            Decrypt(compressedBytes, compressedSize);
            compressedBytes += 0x14;
            compressedSize -= 0x14;
            m_BlocksInfo[i].compressedSize = compressedSize;
        }
        memcpy(blocksStream, compressedBytes, compressedSize);
        blocksStream += compressedSize;

        //https://stackoverflow.com/questions/61443910/what-is-causing-invalid-address-specified-to-rtlvalidateheap-01480000-014a290
        //delete[] compressedBytes;
    }

    // 重新计算解密后的compressedSizeSum
    compressedSizeSum = 0;
    for (int i = 0; i < blocksInfoCount; i++) {
        compressedSizeSum += m_BlocksInfo[i].compressedSize;
    }

    // Output Unity Standard *.unity3d Files
    //string unityFS = "556e697479465300"; // UnityFS\0 (8bit)
    //string ArchiveVersion = "00000006"; // 6 (4bit)
    //string UnityBundleVersion = "352e782e7800"; // 5.x.x\0 (6bit)
    //string ABPackVersion = "323031392E342E38663100"; // 2019.4.8f1\0 (24bit)

    // 获取路径信息总大小
    unsigned int nodesSize = 0;
    for (int i = 0; i < nodesCount; i++)
    {
        nodesSize = nodesSize + 20 + m_DirectoryInfo[i].path.length() + 1; // +1 是天杀的\00
    }

    // headers_size 为 header的大小
    // 20 为 ABPackSize + compressedBlocksInfoSize + uncompressedBlocksInfoSize + flags
    // 20 为区块信息（16bit hash / 4bit blockCount）
    // 10 * blocksInfoCount 为 各区块信息总大小
    // nodesSize 为 路径信息总大小
    // compressedSizeSum 为 blocks 总大小
    unsigned int headers_size = signature.length() + 1 + sizeof(version) + unityVersion.length() + 1 + unityRevisions.length() + 1;
    unsigned __int64 ABPackSize = headers_size + 20 + 20 + (10 * blocksInfoCount) + nodesSize + compressedSizeSum;

    fstream testoutput;
    testoutput.open(outpath, std::ios::binary | std::ios::out);

    char fucking00 = 0x00;
    // 写入 Unity3d文件标准头
    testoutput << signature;
    testoutput.write(&fucking00, 1);
    //testoutput << translate_hex_to_write_to_file(ArchiveVersion);
    string ArchiveVersion = "00000006"; // 6 (4bit)
    testoutput << translate_hex_to_write_to_file(ArchiveVersion);
    testoutput << unityVersion;
    testoutput.write(&fucking00, 1);
    testoutput << unityRevisions;
    testoutput.write(&fucking00, 1);

    // 打包新的BlocksInfoBytes
    unsigned int NewBlocksInfoBytes_Size = 20 + (10 * blocksInfoCount) + 4 + nodesSize;
    std::byte* NewBlocksInfoBytes = new std::byte[NewBlocksInfoBytes_Size];
    std::byte* NewBlocksInfoBytes_Start_Address = NewBlocksInfoBytes;

    // 不复原blockHash 用00填充
    //unsigned __int64 blockHash = 0;
    //memcpy(NewBlocksInfoBytes, &blockHash, 8i64);
    //NewBlocksInfoBytes += 8i64;
    //memcpy(NewBlocksInfoBytes, &blockHash, 8i64);
    //NewBlocksInfoBytes += 8i64;
   
    //复原blockHash
    memcpy(NewBlocksInfoBytes, uncompressedBlocksInfo, 16i64);
    NewBlocksInfoBytes += 16i64;


    // 写入blocksInfoCount
    blocksInfoCount = _byteswap_ulong(blocksInfoCount);
    memcpy(NewBlocksInfoBytes, &blocksInfoCount, 4i64);
    NewBlocksInfoBytes += 4i64;

    // 写入blocksInfo
    for (int i = 0; i < _byteswap_ulong(blocksInfoCount); i++) {
        // 大小端转换
        m_BlocksInfo[i].uncompressedSize = _byteswap_ulong(m_BlocksInfo[i].uncompressedSize);
        memcpy(NewBlocksInfoBytes, &m_BlocksInfo[i].uncompressedSize, 4i64);
        NewBlocksInfoBytes += 4i64;

        m_BlocksInfo[i].compressedSize = _byteswap_ulong(m_BlocksInfo[i].compressedSize);
        memcpy(NewBlocksInfoBytes, &m_BlocksInfo[i].compressedSize, 4i64);
        NewBlocksInfoBytes += 4i64;

        // 如果flags是LZ4_MHY 转为正常的LZ4 flags
        if ((m_BlocksInfo[i].flags & 0x3F) == 0x5) {
            m_BlocksInfo[i].flags = 0x43;
        }
        m_BlocksInfo[i].flags = _byteswap_ushort(m_BlocksInfo[i].flags);
        memcpy(NewBlocksInfoBytes, &m_BlocksInfo[i].flags, 2i64);
        NewBlocksInfoBytes += 2i64;
    }

    // 写入nodesCount
    nodesCount = _byteswap_ulong(nodesCount);
    memcpy(NewBlocksInfoBytes, &nodesCount, 4i64);
    NewBlocksInfoBytes += 4i64;

    // 写入nodes
    for (int i = 0; i < _byteswap_ulong(nodesCount); i++)
    {
        // 这里nodes的offset和size没转大端是因为前面就忘记转小端了 懒得加代码了－O－
        memcpy(NewBlocksInfoBytes, &m_DirectoryInfo[i].offset, 8i64);
        NewBlocksInfoBytes += 8i64;

        memcpy(NewBlocksInfoBytes, &m_DirectoryInfo[i].size, 8i64);
        NewBlocksInfoBytes += 8i64;
        //m_DirectoryInfo[i].size = _byteswap_uint64(m_DirectoryInfo[i].size);

        m_DirectoryInfo[i].flags = _byteswap_ulong(m_DirectoryInfo[i].flags);
        memcpy(NewBlocksInfoBytes, &m_DirectoryInfo[i].flags, 4i64);
        NewBlocksInfoBytes += 4i64;

        char* path_v1 = new char[m_DirectoryInfo[i].path.length()]; 
        path_v1 = (char*)m_DirectoryInfo[i].path.c_str();
        memcpy(NewBlocksInfoBytes, path_v1, m_DirectoryInfo[i].path.length() + 1);// +1 是天杀的\00
        NewBlocksInfoBytes += m_DirectoryInfo[i].path.length() + 1;
    }

    // 将新的BlocksInfoBytes用LZ4压缩
    unsigned int max_dst_size = LZ4_compressBound(NewBlocksInfoBytes_Size);
    std::byte* NewBlocksInfoBytes_LZ4 = new std::byte[max_dst_size];
    unsigned int NewBlocksInfoBytes_compSize = LZ4_compress_default((char*)NewBlocksInfoBytes_Start_Address, (char*)NewBlocksInfoBytes_LZ4, NewBlocksInfoBytes_Size, max_dst_size);

    // 小端转大端
    ABPackSize = _byteswap_uint64(ABPackSize);
    testoutput.write((const char*)&ABPackSize, sizeof(unsigned __int64));

    NewBlocksInfoBytes_compSize = _byteswap_ulong(NewBlocksInfoBytes_compSize);
    testoutput.write((const char*)&NewBlocksInfoBytes_compSize, sizeof(unsigned int));

    NewBlocksInfoBytes_Size = _byteswap_ulong(NewBlocksInfoBytes_Size);
    testoutput.write((const char*)&NewBlocksInfoBytes_Size, sizeof(unsigned int));

    //string ArchiveFlags = "00000043";// LZ4压缩flags
    //testoutput << translate_hex_to_write_to_file(ArchiveFlags);
    testoutput.write(reinterpret_cast<char*>(flag), sizeof(flag));

    // 写入blocksInfoBytes
    testoutput.write((const char*)NewBlocksInfoBytes_LZ4, _byteswap_ulong(NewBlocksInfoBytes_compSize));

    // 写入blocksStream
    testoutput.write((const char*)blocksStream_start_address, compressedSizeSum);
    // 释放内存 免得内存爆炸
    delete[] blocksStream_start_address;
    delete[] NewBlocksInfoBytes_Start_Address;
    delete[] blocksInfoBytes;
    delete[] m_DirectoryInfo;
    delete[] m_BlocksInfo;
    delete[] NewBlocksInfoBytes_LZ4;

    return 0;
}