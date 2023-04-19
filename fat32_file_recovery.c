// Net ID: yz7654
// Created by Yihao Zhong on 2022/12/6.
/* References:
 * primary review and study and artitechture design: https://github.com/g-revanth/FileRecovery-FAT32/blob/0de3a4272aeb258ab792a967c7cf137e8320cd16/FileRecoveryFat32.c
 * getopt(): https://man7.org/linux/man-pages/man3/getopt.3.html
 *              https://developer.aliyun.com/article/623061
 *              https://stackoverflow.com/questions/18079340/using-getopt-in-c-with-non-option-arguments
 *              https://stackoverflow.com/questions/55044365/getopt-usage-with-without-option
 * open(): https://man7.org/linux/man-pages/man2/open.2.html
 *             https://www.dotcpp.com/course/454
 *  switch: https://stackoverflow.com/questions/55693007/error-this-statement-may-fall-through-werror-implicit-fallthrough
 *  unsigned short: https://stackoverflow.com/questions/8699812/what-is-the-format-specifier-for-unsigned-short-int
 *  get file size: https://stackoverflow.com/questions/238603/how-can-i-get-a-files-size-in-c
 *  assign hex: https://stackoverflow.com/questions/10653499/how-to-pack-a-hexadecimal-value-in-an-unsigned-char-variable-in-a-c-program
 *  sha1: https://stackoverflow.com/questions/918676/generate-sha-hash-in-c-using-openssl-library
 *          https://stackoverflow.com/questions/3969047/is-there-a-standard-way-of-representing-an-sha1-hash-as-a-c-string-and-how-do-i%20for%20(int%20k=0;%20k%3CSHA_DIGEST_LENGTH;%20k++)%7B
 *          https://github.com/clibs/sha1
 *          https://stackoverflow.com/questions/9284420/how-to-use-sha1-hashing-in-c-programming
 *          https://stackoverflow.com/questions/62852212/undefined-reference-sha-update-openssl-in-c
 *          https://stackoverflow.com/questions/64069399/understanding-the-sha1-update-and-sha1-final-functions
 *
    memcpy: https://www.tutorialspoint.com/c_standard_library/c_function_memcpy.htm

    combination: https://www.sanfoundry.com/c-program-generate-possible-combinations-given-list-numbers/
    https://www.geeksforgeeks.org/print-all-possible-combinations-of-r-elements-in-a-given-array-of-size-n/

    backtracking: https://leetcode.com/problems/permutations/solutions/18369/c-recursion-with-diagram-explanation/?q=C&orderBy=most_relevant
    https://www.geeksforgeeks.org/c-program-to-print-all-permutations-of-a-given-string/


 * */
#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <openssl/sha.h>

#define SHA_DIGEST_LENGTH 20
#define SHA_DIGEST_LENGTH 20

#pragma pack(push,1)
typedef struct BootEntry {
    unsigned char  BS_jmpBoot[3];     // Assembly instruction to jump to boot code
    unsigned char  BS_OEMName[8];     // OEM Name in ASCII
    unsigned short BPB_BytsPerSec;    // Bytes per sector. Allowed values include 512, 1024, 2048, and 4096
    unsigned char  BPB_SecPerClus;    // Sectors per cluster (data unit). Allowed values are powers of 2, but the cluster size must be 32KB or smaller
    unsigned short BPB_RsvdSecCnt;    // Size in sectors of the reserved area
    unsigned char  BPB_NumFATs;       // Number of FATs
    unsigned short BPB_RootEntCnt;    // Maximum number of files in the root directory for FAT12 and FAT16. This is 0 for FAT32
    unsigned short BPB_TotSec16;      // 16-bit value of number of sectors in file system
    unsigned char  BPB_Media;         // Media type
    unsigned short BPB_FATSz16;       // 16-bit size in sectors of each FAT for FAT12 and FAT16. For FAT32, this field is 0
    unsigned short BPB_SecPerTrk;     // Sectors per track of storage device
    unsigned short BPB_NumHeads;      // Number of heads in storage device
    unsigned int   BPB_HiddSec;       // Number of sectors before the start of partition
    unsigned int   BPB_TotSec32;      // 32-bit value of number of sectors in file system. Either this value or the 16-bit value above must be 0
    unsigned int   BPB_FATSz32;       // 32-bit size in sectors of one FAT
    unsigned short BPB_ExtFlags;      // A flag for FAT
    unsigned short BPB_FSVer;         // The major and minor version number
    unsigned int   BPB_RootClus;      // Cluster where the root directory can be found
    unsigned short BPB_FSInfo;        // Sector where FSINFO structure can be found
    unsigned short BPB_BkBootSec;     // Sector where backup copy of boot sector is located
    unsigned char  BPB_Reserved[12];  // Reserved
    unsigned char  BS_DrvNum;         // BIOS INT13h drive number
    unsigned char  BS_Reserved1;      // Not used
    unsigned char  BS_BootSig;        // Extended boot signature to identify if the next three values are valid
    unsigned int   BS_VolID;          // Volume serial number
    unsigned char  BS_VolLab[11];     // Volume label in ASCII. User defines when creating the file system
    unsigned char  BS_FilSysType[8];  // File system type label in ASCII
} BootEntry;
#pragma pack(pop)

#pragma pack(push,1)
typedef struct DirEntry {
    unsigned char  DIR_Name[11];      // File name
    unsigned char  DIR_Attr;          // File attributes
    unsigned char  DIR_NTRes;         // Reserved
    unsigned char  DIR_CrtTimeTenth;  // Created time (tenths of second)
    unsigned short DIR_CrtTime;       // Created time (hours, minutes, seconds)
    unsigned short DIR_CrtDate;       // Created day
    unsigned short DIR_LstAccDate;    // Accessed day
    unsigned short DIR_FstClusHI;     // High 2 bytes of the first cluster address
    unsigned short DIR_WrtTime;       // Written time (hours, minutes, seconds
    unsigned short DIR_WrtDate;       // Written day
    unsigned short DIR_FstClusLO;     // Low 2 bytes of the first cluster address
    unsigned int   DIR_FileSize;      // File size in bytes. (0 for directories)
} DirEntry;
#pragma pack(pop)
char** possibleList;
int count;
char* correctClusterComb;
void swap(char* x, char* y)
{
    char temp = *x;
    *x = *y;
    *y = temp;
}
int permu(char *a, int size, int idx)
{
    int i =idx;

    if (idx ==size){
        possibleList[count] = (char*) malloc(sizeof (char) * size);
        correctClusterComb = (char*) malloc(sizeof (char) * size);
        strcpy(possibleList[count], a);
        count += 1;
        return 0;
    }

    /* Loop generating the sequence for this offset location */
    while (i < size){
        // Pick a new value for the location
        swap(a+idx, a+i);
        // Recursively generate permutations for the remaining
        if (permu(a, size, idx + 1))
            return -1;
        // Reverse the change at that index
        swap(a+idx, a+i);
        i++;
    }
    return 0;
}

void combination(char input[], char result[], int startIndex, int endIndex, int currIndex, int size){
    if(currIndex == size){
        char* tempArray = malloc(sizeof (char)* size);
        strcpy(tempArray, result);
        permu(tempArray,size, 0);
//        possibleList[count] = (char*) malloc(sizeof (char) * size);
//        strcpy (possibleList[count] ,tempArray);
//        count++;
        return;
    }
    int i = startIndex;
    while((i < endIndex) && (i <= endIndex+currIndex-size+1)){
        result[currIndex] = input[i];
        combination(input, result, i+1, endIndex, currIndex+1, size);
        i++;
    }

}


void print_usage(){
    printf("Usage: ./nyufile disk <options>\n");
    printf("  -i                     Print the file system information.\n");
    printf("  -l                     List the root directory.\n");
    printf("  -r filename [-s sha1]  Recover a contiguous file.\n");
    printf("  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
}

bool checkMatch(DirEntry* my_dirEntry, unsigned char* file){
    bool matchedFileName = true;
    int nameLength = 1;
    unsigned char tempFileName[11];
    for (int i = 1; i < 11; i++) {
        if ((i == 8) && (my_dirEntry->DIR_Name[8] != ' ') && (my_dirEntry->DIR_Name[0] != 0x00)){
            tempFileName[nameLength] = '.';
            nameLength ++;
        }
        if (my_dirEntry->DIR_Name[i] != ' '){
            tempFileName[nameLength] = my_dirEntry->DIR_Name[i];
            nameLength ++;
        }

    }
    for (int i = 1; i < nameLength; i++) {
        if (tempFileName[i] != file[i])
            matchedFileName = false;
    }
    return matchedFileName;
}

int main(int argc, char * argv[]) {
    int opt ;
    // flag to identify calls: 0 not called, 1 called
    int call_i, call_l,  call_r, call_R, call_s;
    bool isValid = true;
    call_i = call_l = call_r = call_R = call_s = 0;
    // getopt sets the optind variable to indicate the position of the next argument.
    opterr = 0; //get rid of error msg

    // file to be recoved
    unsigned char* file;
    unsigned char* sha_input;
    while ((opt = getopt(argc, argv, "ilr:R:s:")) != -1){
        // NO MORE opt after i and l, only -i and -l
        // r/R can be followed by s, or nothing
        switch (opt){
            case 'i': // print the fs info
                call_i = 1;
                if (call_R || call_r || call_l || call_s){
                    print_usage();
                    isValid = false;
                    break;
                }

                break;

            case 'l': // list the root dir
                call_l = 1;
                if (call_R || call_r || call_i || call_s){
                    print_usage();
                    isValid = false;
                    break;
                }
                break;

            case 'r': // recover a contiguous file
                call_r = 1;
                if (call_R || call_l || call_i || call_s){
                    print_usage();
                    isValid = false;
                    break;
                }
                // get the file name
                // // command line read in is char * , but the dir name is unsigned char
                file = (unsigned  char*) optarg;
                break;

            case 'R': // recover possibly non-contiguous file
                call_R = 1;
                if (call_r || call_l || call_i || call_s){
                    print_usage();
                    isValid = 0;
                    break;
                }
                file = (unsigned  char*) optarg;
                break;
                //printf("here is %s\n",optarg);
                //printf("here is  j;\n");

            case 's':
                call_s = 1;
                if ((call_i == 1) || (call_l == 1)){
                    print_usage();
                    isValid = 0;
                    break;
                }
                sha_input = (unsigned  char*) optarg;
                break;

            case '?': // invalid command, print usage information
                print_usage();
                isValid = 0;
                break;

            default:
                print_usage();
                isValid = 0;
                break;
        }
    }
    // if no option is passed, only ./nyufile
    if (!isValid){
        return 0;
    }
    if (argc == 1){
        print_usage();
        return 0;
    }
    //printf("can you reach here>");
    // read in the disk FAT32
    /*
     *You may need to open the disk image with O_RDWR
     * and map it with PROT_READ | PROT_WRITE and MAP_SHARED
     */
    struct stat sb;
    char *addr;

    // open the fat32.disk
    int fp = open(argv[optind], O_RDWR);
    if (fp == -1){
        print_usage();
        return 0;
    }
    fstat(fp, &sb);         /* To obtain file size */
    addr = mmap(NULL, sb.st_size,PROT_READ | PROT_WRITE,MAP_SHARED, fp, 0);

    // map the correponding area to FS STRUCT
    BootEntry *my_disk = (BootEntry*) addr;

    // case: -i
    if (call_i == 1){
        printf("Number of FATs = %d\n", my_disk->BPB_NumFATs);
        printf("Number of bytes per sector = %d\n", my_disk->BPB_BytsPerSec);
        printf("Number of sectors per cluster = %d\n", my_disk->BPB_SecPerClus);
        printf("Number of reserved sectors = %d\n", my_disk->BPB_RsvdSecCnt);
    }

    // mile stone 3
    // create a directory, we need to find it
    // boot sector -> 2 FAT -> Data area (BPB_RootClus define the start location of the root dir)

    // FAT
    // that is after reserved sector (# of reserved sector * Byte per sector) 512 * 32 = starting at 1634

    unsigned int * fat = (unsigned int *) (addr + (my_disk->BPB_BytsPerSec * my_disk->BPB_RsvdSecCnt));
//    unsigned int tem = 0;
//    while(fat[tem] != 0){
//        printf("%x ", fat[tem]);
//        tem ++;
//    }


    // DATA AREA
    // that is after all FATs, area of FAT is (# of FAT * 32 size of FAT), then plus the reserved sector area
    unsigned int begin_data_area = ((my_disk->BPB_BytsPerSec * my_disk->BPB_RsvdSecCnt) + (my_disk->BPB_NumFATs*my_disk->BPB_FATSz32*my_disk->BPB_BytsPerSec));

//    printf("BPB_RootClus is %d\n", my_disk->BPB_RootClus);
//    printf("begin_root_dir is %d\n", begin_root_dir); // 20480
//    printf("begin_data_area is %d\n", begin_data_area);

    // the begin of root dir, the first dir
    if (call_l == 1) {
        int count_entries = 0;

        unsigned int fat_cluster = my_disk->BPB_RootClus;
        while (fat_cluster <= 0x0ffff8){
            int num_of_dir_per_clus_index = 0;
            unsigned int begin_root_dir =
                    begin_data_area + (fat_cluster - 2) * (my_disk->BPB_BytsPerSec * my_disk->BPB_SecPerClus);
            while (num_of_dir_per_clus_index < (my_disk->BPB_BytsPerSec * my_disk->BPB_SecPerClus)) {
                DirEntry *my_dirEntry = (DirEntry *) (addr + begin_root_dir + num_of_dir_per_clus_index);
                if (my_dirEntry->DIR_Name[0] == 0x00) break;
                if (my_dirEntry->DIR_Name[0] != 0xe5) {
                    // empty file
                    if ((my_dirEntry->DIR_FileSize == 0) && (my_dirEntry->DIR_Attr != 0x10)) {
//                        for (int i = 0; i < 11; i++) {
//                            if (my_dirEntry->DIR_Name[i] != ' ')
//                                printf("%c", my_dirEntry->DIR_Name[i]);
//                        }

                        for (int i = 0; i < 11; i++) {
                            if ((i == 8) && (my_dirEntry->DIR_Name[8] != ' ') && (my_dirEntry->DIR_Name[0] != 0x00))
                                printf(".");
                            if (my_dirEntry->DIR_Name[i] != ' ')
                                printf("%c", my_dirEntry->DIR_Name[i]);
                        }
                        printf(" (size = %d, starting cluster = %d)\n", my_dirEntry->DIR_FileSize,
                               (my_dirEntry->DIR_FstClusHI << 16) + my_dirEntry->DIR_FstClusLO);
                        count_entries++;
                    }
                        // directory
                    else if (my_dirEntry->DIR_Attr == 0x10) {

//                        for (int i = 0; i < 11; i++) {
//                            if (my_dirEntry->DIR_Name[i] != ' ')
//                                printf("%c", my_dirEntry->DIR_Name[i]);
//                        }
                        for (int i = 0; i < 11; i++) {
                            if ((i == 8) && (my_dirEntry->DIR_Name[8] != ' ') && (my_dirEntry->DIR_Name[0] != 0x00))
                                printf(".");
                            if (my_dirEntry->DIR_Name[i] != ' ')
                                printf("%c", my_dirEntry->DIR_Name[i]);
                        }
                        printf("/");
                        printf(" (size = %d, starting cluster = %d)\n", my_dirEntry->DIR_FileSize,
                               (my_dirEntry->DIR_FstClusHI << 16) + my_dirEntry->DIR_FstClusLO);
                        count_entries++;
                    }
                        // a file
                    else {
                        for (int i = 0; i < 11; i++) {
                            if ((i == 8) && (my_dirEntry->DIR_Name[8] != ' ') && (my_dirEntry->DIR_Name[0] != 0x00))
                                printf(".");
                            if (my_dirEntry->DIR_Name[i] != ' ')
                                printf("%c", my_dirEntry->DIR_Name[i]);
                        }
                        printf(" (size = %d, starting cluster = %d)\n", my_dirEntry->DIR_FileSize,
                               (my_dirEntry->DIR_FstClusHI << 16) + my_dirEntry->DIR_FstClusLO);
                        count_entries++;
                    }
                }

                num_of_dir_per_clus_index += 32;
            }
            fat_cluster = *(fat+fat_cluster);
        }
        printf("Total number of entries = %d\n", count_entries);
    }

    // mile stone 4
    if (call_r == 1 && call_s ==0) {
        int num_of_found_file = 0;
        unsigned int fat_cluster = my_disk->BPB_RootClus;

        // first we check all the directory : check multiple candidates milestone 5
        while (fat_cluster <= 0x0ffff8) {
            int num_of_dir_per_clus_index = 0;
            unsigned int begin_root_dir =
                    begin_data_area + (fat_cluster - 2) * (my_disk->BPB_BytsPerSec * my_disk->BPB_SecPerClus);
            while (num_of_dir_per_clus_index < (my_disk->BPB_BytsPerSec * my_disk->BPB_SecPerClus)) {
                DirEntry *my_dirEntry = (DirEntry *) (addr + begin_root_dir + num_of_dir_per_clus_index);
                if (my_dirEntry->DIR_Name[0] == 0x00) break;
                if (my_dirEntry->DIR_Name[0] == 0xe5) {
                    if (checkMatch(my_dirEntry, file))
                        num_of_found_file++;
                }
                num_of_dir_per_clus_index += 32;
            }
            fat_cluster = *(fat+fat_cluster);
        }

        if (num_of_found_file > 1) {
            printf("%s: multiple candidates found\n", file);
        }
        else if (num_of_found_file == 0){
            printf("%s: file not found\n", file);
        }
        else {
            fat = (unsigned int *) (addr + (my_disk->BPB_BytsPerSec * my_disk->BPB_RsvdSecCnt));
            fat_cluster = my_disk->BPB_RootClus;
            while (fat_cluster <= 0x0ffff8) {
                int num_of_dir_per_clus_index = 0;
                unsigned int begin_root_dir =
                        begin_data_area + (fat_cluster - 2) * (my_disk->BPB_BytsPerSec * my_disk->BPB_SecPerClus);
                while (num_of_dir_per_clus_index < (my_disk->BPB_BytsPerSec * my_disk->BPB_SecPerClus)) {
                    DirEntry *my_dirEntry = (DirEntry *) (addr + begin_root_dir + num_of_dir_per_clus_index);
                    if (my_dirEntry->DIR_Name[0] == 0x00) break;
                    if (my_dirEntry->DIR_Name[0] == 0xe5) {

                        if (checkMatch(my_dirEntry, file)) {
                            // empty file, not need to update FAT
                            if ((my_dirEntry->DIR_FileSize == 0) && (my_dirEntry->DIR_Attr != 0x10)) {
                                my_dirEntry->DIR_Name[0] = file[0];
                            }
                                // a file
                            else {
                                my_dirEntry->DIR_Name[0] = file[0];

                                // we are not updating the content !!!
//                                unsigned char* start_of_cluster = (unsigned char *) (addr + begin_data_area + ((my_dirEntry->DIR_FstClusHI * 10 + my_dirEntry->DIR_FstClusLO) - 2)
//                                            * (my_disk->BPB_BytsPerSec * my_disk->BPB_SecPerClus));
//                                for(int i = 1; i <= 6; i++){
//                                    start_of_cluster[i] = 0xf;
//                                }
//                                start_of_cluster[7] = 0x0;
//                                start_of_cluster[8] = 0xf;
                                for (int n = 0; n <my_disk->BPB_NumFATs; n++){
                                    unsigned int incred = 1;
                                    unsigned char start_of_fat = ((my_dirEntry->DIR_FstClusHI << 16) + my_dirEntry->DIR_FstClusLO) + n*(my_disk->BPB_BytsPerSec*my_disk->BPB_FATSz32);
                                    for(unsigned int idx = 0; idx < my_dirEntry->DIR_FileSize; idx += (my_disk->BPB_BytsPerSec * my_disk->BPB_SecPerClus)){
                                        *(fat + (incred -1 + start_of_fat))
                                                =  (my_dirEntry->DIR_FstClusHI << 16) + my_dirEntry->DIR_FstClusLO + incred;
                                        incred ++;
                                    }
                                    *(fat + (incred -1 + start_of_fat)) = 0xfffffff;
                                }

                            }
                            printf("%s: successfully recovered\n", file);

                        }
                    }
                    num_of_dir_per_clus_index += 32;
                }
                fat_cluster = *(fat+fat_cluster);
            }

        }
    }

    if (call_r == 1 && call_s == 1) {
        int num_of_found_file = 0;
        unsigned int fat_cluster = my_disk->BPB_RootClus;

        // first we check all the directory : check multiple candidates milestone 7

        fat = (unsigned int *) (addr + (my_disk->BPB_BytsPerSec * my_disk->BPB_RsvdSecCnt));
        fat_cluster = my_disk->BPB_RootClus;

        // loop every file in the root dir
        bool end_milestone = false;
        //int itr = 0;
        while ((fat_cluster <= 0x0ffff8) && (end_milestone == false)) {
            int num_of_dir_per_clus_index = 0;
            unsigned int begin_root_dir =
                    begin_data_area + (fat_cluster - 2) * (my_disk->BPB_BytsPerSec * my_disk->BPB_SecPerClus);

            while ((num_of_dir_per_clus_index < (my_disk->BPB_BytsPerSec * my_disk->BPB_SecPerClus)) && (end_milestone == false)) {

                // each root dir <-> each file
                DirEntry *my_dirEntry = (DirEntry *) (addr + begin_root_dir + num_of_dir_per_clus_index);

                if (my_dirEntry->DIR_Name[0] == 0x00) break;
                if (my_dirEntry->DIR_Name[0] == 0xe5) {
                    // if found the potential matched one
                    if (checkMatch(my_dirEntry, file)) {
                        num_of_found_file++;

                        // SHA
                        unsigned char hash[SHA_DIGEST_LENGTH];
                        char hash_40[SHA_DIGEST_LENGTH*2];


                        // empty file, not need to update FAT
                        if ((my_dirEntry->DIR_FileSize == 0) && (my_dirEntry->DIR_Attr != 0x10)) {
                            // get the sha code of the empty file
                            char data[] = "";
                            size_t data_length = strlen(data);
                            SHA1((const unsigned char*)data, data_length, hash);
                            for(int i = 0; i<SHA_DIGEST_LENGTH; i++) {
                                sprintf((char*)&hash_40[i*2], "%02x", hash[i]);
                            }
                            if (strcmp(hash_40, (char *)sha_input) == 0){
                                my_dirEntry->DIR_Name[0] = file[0];
                                printf("%s: successfully recovered with SHA-1\n", file);
                                end_milestone = true;
                                break;
                            }

                        }
                            // a file
                        else {


                            // we are not updating the content !!!
//                                unsigned char* start_of_cluster = (unsigned char *) (addr + begin_data_area + ((my_dirEntry->DIR_FstClusHI <<16 + my_dirEntry->DIR_FstClusLO) - 2)
//                                            * (my_disk->BPB_BytsPerSec * my_disk->BPB_SecPerClus));
                            // read the content
                            unsigned int offset = 0;
//                            SHA_CTX sha_ctx;
//                            SHA1_Init(&sha_ctx);

                            unsigned int last_content_clus_quotient = (my_dirEntry->DIR_FileSize) / (my_disk->BPB_BytsPerSec * my_disk->BPB_SecPerClus);
                            unsigned int last_content_clus_reminder = (my_dirEntry->DIR_FileSize) % (my_disk->BPB_BytsPerSec * my_disk->BPB_SecPerClus);
                            //printf("the file size is %u, quotient is %u, rem is %u \n", (my_dirEntry->DIR_FileSize), last_content_clus_quotient, last_content_clus_reminder);
//                            unsigned char temphash[SHA_DIGEST_LENGTH];
//                            unsigned char temphash_40[SHA_DIGEST_LENGTH*2];
                            unsigned char* buffer = malloc((my_dirEntry->DIR_FileSize+1) * sizeof (unsigned char));
//                            unsigned char buffer[(my_dirEntry->DIR_FileSize+1)];
                            for(unsigned int idx = 0; idx < my_dirEntry->DIR_FileSize; idx += (my_disk->BPB_BytsPerSec * my_disk->BPB_SecPerClus)){
                                unsigned char* start_of_cluster = (unsigned char *) (addr + begin_data_area + (((my_dirEntry->DIR_FstClusHI <<16) + my_dirEntry->DIR_FstClusLO) - 2+offset)
                                                                                                              * (my_disk->BPB_BytsPerSec * my_disk->BPB_SecPerClus));
                                if (offset == last_content_clus_quotient){
//                                    unsigned char buffer[last_content_clus_reminder];
                                    memcpy(buffer+idx, start_of_cluster, last_content_clus_reminder);
                                    //printf("offset is % d, length of buffer is: %lu, clus_size is: %d, buffer is: %s \n", offset,
                                    //       strlen((char*)buffer), last_content_clus_reminder, buffer);
//                                    SHA1_Update(&sha_ctx, "My last name is Tang.", last_content_clus_reminder);
                                    //SHA1((const unsigned char*)buffer, last_content_clus_reminder, temphash);
//                                    for(int i = 0; i<SHA_DIGEST_LENGTH; i++) {
//                                        sprintf((char*)&temphash_40[i*2], "%02x", temphash[i]);
//                                    }
//                                    printf("Temp Hash: %s\n", temphash_40);
                                }
                                else{
//                                    unsigned char buffer[(my_disk->BPB_BytsPerSec * my_disk->BPB_SecPerClus)];
                                    memcpy(buffer+idx, start_of_cluster, (my_disk->BPB_BytsPerSec * my_disk->BPB_SecPerClus));
                                    //printf("offset is % d buffer is: %s \n", offset, buffer);
//                                    SHA1_Update(&sha_ctx, &buffer,(my_disk->BPB_BytsPerSec * my_disk->BPB_SecPerClus));
                                }

                                offset++;
                            }
                            //SHA1_Final(hash, &sha_ctx);
                            SHA1((const unsigned char*)buffer, my_dirEntry->DIR_FileSize, hash);
                            for(int i = 0; i<SHA_DIGEST_LENGTH; i++) {
                                sprintf((char*)&hash_40[i*2], "%02x", hash[i]);
                            }
                            //printf("Hash: %s\n", hash_40);
                            if (strcmp(hash_40, (char *)sha_input) == 0){
                                my_dirEntry->DIR_Name[0] = file[0];
                                for (int n = 0; n <my_disk->BPB_NumFATs; n++){
                                    unsigned int incred = 1;
                                    unsigned char start_of_fat = ((my_dirEntry->DIR_FstClusHI << 16) + my_dirEntry->DIR_FstClusLO) + n*(my_disk->BPB_BytsPerSec*my_disk->BPB_FATSz32);
                                    for(unsigned int idx = 0; idx < my_dirEntry->DIR_FileSize; idx += (my_disk->BPB_BytsPerSec * my_disk->BPB_SecPerClus)){
                                        *(fat + (incred -1 + start_of_fat))
                                                = ((my_dirEntry->DIR_FstClusHI << 16) + my_dirEntry->DIR_FstClusLO) + incred;
                                        incred ++;
                                    }
                                    *(fat + (incred -1 + start_of_fat)) = 0xfffffff;
                                }
                                printf("%s: successfully recovered with SHA-1\n", file);
                                end_milestone = true;
                                break;
                            }
                            // update the fat
                        }
                    }
                }
                //printf("iteration is %d \n", itr);
                //itr ++;
                num_of_dir_per_clus_index += 32;
            }
            fat_cluster = *(fat+fat_cluster);
        }
        if ((num_of_found_file == 0) || (end_milestone == false)){
            printf("%s: file not found\n", file);
        }


    }
    //char empty_sha[40] = "da39a3ee5e6b4b0d3255bfef95601890afd80709"; // 20 char
//    unsigned char hash[SHA_DIGEST_LENGTH];
//    char hash_40[SHA_DIGEST_LENGTH*2];
//    char data[] = "";
//    size_t data_length = strlen(data);
//    SHA1((const unsigned char*)data, data_length, hash);
//    for(int i = 0; i<SHA_DIGEST_LENGTH; i++) {
//        sprintf((char*)&hash_40[i*2], "%02x", hash[i]);
//    }
//    printf("Hash: %s\n", hash_40);
//    printf("Hash1: %s\n", empty_sha);
//    printf("%d", strcmp(hash_40, "da39a3ee5e6b4b0d3255bfef95601890afd80709"));
//
      //printf("input Hash: %s\n", sha_input);
//    SHA_CTX sha_ctx;
//    SHA1_Init(&sha_ctx);
//    SHA1_Update(&sha_ctx, "My last name is Tang.", 22);
//    SHA1_Final(hash, &sha_ctx);
//    for(int i = 0; i<SHA_DIGEST_LENGTH; i++) {
//        sprintf((char*)&hash_40[i*2], "%02x", hash[i]);
//    }
//    printf("Hash: %s\n", hash_40);

//    printf("hello");
//    printf("the cluster in fat is %d", fat[my_disk->BPB_RootClus]);


    if (call_R == 1 && call_s == 1) {
        int num_of_found_file = 0;
        unsigned int fat_cluster = my_disk->BPB_RootClus;

        // first we check all the directory : check multiple candidates milestone 7

        fat = (unsigned int *) (addr + (my_disk->BPB_BytsPerSec * my_disk->BPB_RsvdSecCnt));
        fat_cluster = my_disk->BPB_RootClus;

        // We create a permutation list, using all FAT table entries that has '0', for example 3 (start) -> [2, 7, 8], [2, 8, 7], [7,2,8], [7,8,2], [8,7,2], [8,2,7] (3*2*1 = 6)



        // loop every file in the root dir
        bool end_milestone = false;
        //int itr = 0;
        while ((fat_cluster <= 0x0ffff8) && (end_milestone == false)) {
            int num_of_dir_per_clus_index = 0;
            unsigned int begin_root_dir =
                    begin_data_area + (fat_cluster - 2) * (my_disk->BPB_BytsPerSec * my_disk->BPB_SecPerClus);

            while ((num_of_dir_per_clus_index < (my_disk->BPB_BytsPerSec * my_disk->BPB_SecPerClus)) && (end_milestone == false)) {

                // each root dir <-> each file
                DirEntry *my_dirEntry = (DirEntry *) (addr + begin_root_dir + num_of_dir_per_clus_index);

                if (my_dirEntry->DIR_Name[0] == 0x00) break;
                if (my_dirEntry->DIR_Name[0] == 0xe5) {
                    // if found the potential matched one
                    if (checkMatch(my_dirEntry, file)) {
                        num_of_found_file++;

                        // SHA
                        unsigned char hash[SHA_DIGEST_LENGTH];
                        char hash_40[SHA_DIGEST_LENGTH*2];


                        // empty file, not need to update FAT
                        if ((my_dirEntry->DIR_FileSize == 0) && (my_dirEntry->DIR_Attr != 0x10)) {
                            // get the sha code of the empty file
                            char data[] = "";
                            size_t data_length = strlen(data);
                            SHA1((const unsigned char*)data, data_length, hash);
                            for(int i = 0; i<SHA_DIGEST_LENGTH; i++) {
                                sprintf((char*)&hash_40[i*2], "%02x", hash[i]);
                            }
                            if (strcmp(hash_40, (char *)sha_input) == 0){
                                my_dirEntry->DIR_Name[0] = file[0];
                                printf("%s: successfully recovered with SHA-1\n", file);
                                end_milestone = true;
                                break;
                            }

                        }
                            // a file
                        else if ((my_dirEntry->DIR_FileSize) > (my_disk->BPB_BytsPerSec * my_disk->BPB_SecPerClus)){
                            // every thing is in 2 - 21 (or more) cluster, and at most have 5 clusters
                            int c = 0;
                            // loop the fat
                            int loop_fat = 2;
                            char possibleCluster[(my_disk->BPB_BytsPerSec/32)];
                            memset(possibleCluster, 0, sizeof possibleCluster);

                            while (loop_fat < my_disk->BPB_BytsPerSec/32){
                                if (*(fat+loop_fat) == 0){
                                    unsigned char* start_of_cluster = (unsigned char *) (addr + begin_data_area + ((loop_fat-2)*(my_disk->BPB_BytsPerSec * my_disk->BPB_SecPerClus)));
                                    if ((*start_of_cluster != 0) && (loop_fat!=(my_dirEntry->DIR_FstClusHI <<16) + my_dirEntry->DIR_FstClusLO)){
                                        possibleCluster[c] = (char) (loop_fat);
                                        c++;
                                    }
                                }
                                loop_fat++;
                            }
//                            printf("count is %d", c);
                            int ii = 0;
                            char posClus[c];
                            while(possibleCluster[ii] != 0){
                                //printf("array is %d\n", possibleCluster[ii]);
                                posClus[ii] = possibleCluster[ii];
                                //printf("array is %d\n", posClus[ii]);
                                ii++;
                            }

                            count = 0;
                            possibleList = malloc(sizeof (char*) * 1860480);
                            int n = sizeof posClus/sizeof posClus[0];
                            unsigned int num_of_clus = 0;
                            // not include the start cluster
                            if ((my_dirEntry->DIR_FileSize) % (my_disk->BPB_BytsPerSec * my_disk->BPB_SecPerClus)!= 0){
                                num_of_clus = (my_dirEntry->DIR_FileSize) / (my_disk->BPB_BytsPerSec * my_disk->BPB_SecPerClus);
                            }
                            else{
                                num_of_clus = (my_dirEntry->DIR_FileSize) / (my_disk->BPB_BytsPerSec * my_disk->BPB_SecPerClus)-1;
                            }
//                            printf("num_ of clus is %d\n", num_of_clus);
                            char temp[num_of_clus];
                            combination(posClus, temp, 0, n, 0, (int) num_of_clus);
                            int kix = 0;
//                            while (possibleList[kix]!= NULL){
//                                for(unsigned int k = 0; k< num_of_clus; k++){
//                                    printf("%d ", possibleList[kix][k]);
//                                }
//                                kix ++;
//                                printf("|");
//                            }
//                            possibleList[kix] =  malloc(sizeof (char)* 3);
//                            possibleList[kix][0] = (char) 5;
//                            possibleList[kix][1] = (char) 4;
//                            possibleList[kix][2] = (char) 6;
//                            for(unsigned int k = 0; k< num_of_clus; k++){
//                                printf("%d ", possibleList[kix][k]);
//                            }
//                            printf("|");

                            kix = 0;

                            while (possibleList[kix]!= NULL) {
                                unsigned char *buffer = malloc(
                                        (my_dirEntry->DIR_FileSize) * sizeof(unsigned char));
//                                printf("size of char is: %lu", (my_dirEntry->DIR_FileSize) * sizeof(unsigned char));
                                unsigned int offset = 0;
                                unsigned int last_content_clus_quotient = (my_dirEntry->DIR_FileSize) /
                                                                          (my_disk->BPB_BytsPerSec *
                                                                           my_disk->BPB_SecPerClus);
                                unsigned int last_content_clus_reminder = (my_dirEntry->DIR_FileSize) %
                                                                          (my_disk->BPB_BytsPerSec *
                                                                           my_disk->BPB_SecPerClus);
                                //printf("qu is %d", last_content_clus_quotient);
                                memcpy(buffer, (unsigned char *) (addr + begin_data_area +
                                                                  (- 2 +((my_dirEntry->DIR_FstClusHI <<16) + my_dirEntry->DIR_FstClusLO))
                                                                  * (my_disk->BPB_BytsPerSec * my_disk->BPB_SecPerClus)),
                                       (my_disk->BPB_BytsPerSec * my_disk->BPB_SecPerClus));
                                //printf("offset is % d buffer is: %s \n", offset, buffer);
                                int k = 0;
//                                int yy = 0;
                                for (unsigned int idx = (my_disk->BPB_BytsPerSec *
                                                         my_disk->BPB_SecPerClus);
                                     idx < my_dirEntry->DIR_FileSize; idx += (my_disk->BPB_BytsPerSec *
                                                                              my_disk->BPB_SecPerClus)) {
//                                    printf("current k is %d", possibleList[kix][k]);
//                                    if (possibleList[kix][k] == 4)
//                                        yy = 1;
                                    //printf("current idx ois %d", idx);
                                    unsigned char *start_of_cluster = (unsigned char *) (addr + begin_data_area +
                                            ((int)possibleList[kix][k] - 2) * (my_disk->BPB_BytsPerSec * my_disk->BPB_SecPerClus));
                                    if (offset == last_content_clus_quotient-1) {
//                                    unsigned char buffer[last_content_clus_reminder];
                                        memcpy(buffer + idx, start_of_cluster, last_content_clus_reminder);

                                    } else {
//                                    unsigned char buffer[(my_disk->BPB_BytsPerSec * my_disk->BPB_SecPerClus)];
                                        memcpy(buffer + idx, start_of_cluster,
                                               (my_disk->BPB_BytsPerSec * my_disk->BPB_SecPerClus));
                                        //printf("offset is % d buffer is: %s \n", offset, buffer);
//                                    SHA1_Update(&sha_ctx, &buffer,(my_disk->BPB_BytsPerSec * my_disk->BPB_SecPerClus));
                                    }
                                    k++;
                                    offset++;
                                }

                                    //SHA1_Final(hash, &sha_ctx);
                                    //if (yy == 1)
                                        //printf("%d", yy);
                                        //printf("offset is % d buffer is: %s \n", offset, buffer);
                                    SHA1((const unsigned char *) buffer, my_dirEntry->DIR_FileSize, hash);
                                    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
                                        sprintf((char *) &hash_40[i * 2], "%02x", hash[i]);
                                    }
//                                    printf("Hash: %s\n", hash_40);
                                    if (strcmp(hash_40, (char *) sha_input) == 0) {
                                        my_dirEntry->DIR_Name[0] = file[0];
                                        strcpy(correctClusterComb, possibleList[kix]);
                                        //unsigned char start_of_fat;
                                        for (unsigned char np = 0; np < my_disk->BPB_NumFATs; np++) {
                                            fat = (unsigned int *) (addr + (my_disk->BPB_BytsPerSec * my_disk->BPB_RsvdSecCnt));
                                            unsigned int incred = 1;
                                            //start_of_fat = (unsigned char)((my_dirEntry->DIR_FstClusHI << 16) + my_dirEntry->DIR_FstClusLO) + (np * (my_disk->BPB_BytsPerSec * my_disk->BPB_FATSz32));
//                                            printf("Round is %d", np*(my_disk->BPB_BytsPerSec * my_disk->BPB_FATSz32));
//                                            printf("Round is %d", ((my_dirEntry->DIR_FstClusHI << 16) + my_dirEntry->DIR_FstClusLO) + (np * (my_disk->BPB_BytsPerSec * my_disk->BPB_FATSz32)));
//                                            printf("correct Cluster is %d\n", correctClusterComb[0]);
//                                            printf("before the fat is %d\n", *(fat + ((my_dirEntry->DIR_FstClusHI << 16) + my_dirEntry->DIR_FstClusLO) + (np * (my_disk->BPB_BytsPerSec * my_disk->BPB_FATSz32))/4));
                                            *(fat + ((my_dirEntry->DIR_FstClusHI << 16) + my_dirEntry->DIR_FstClusLO) + (np * (my_disk->BPB_BytsPerSec * my_disk->BPB_FATSz32))/4)
                                                    = (unsigned char) correctClusterComb[0];
//                                            printf("after the fat is %d\n", *(fat + ((my_dirEntry->DIR_FstClusHI << 16) + my_dirEntry->DIR_FstClusLO) + (np * (my_disk->BPB_BytsPerSec * my_disk->BPB_FATSz32))/4));
                                            for (unsigned int idx = (my_disk->BPB_BytsPerSec *
                                                                     my_disk->BPB_SecPerClus);
                                                 idx < my_dirEntry->DIR_FileSize; idx += (my_disk->BPB_BytsPerSec *
                                                                                          my_disk->BPB_SecPerClus)) {

                                                //printf("correct Cluster is %d\n", correctClusterComb[incred-1]);
//                                                printf("before the fat is %d\n",  iidex);
                                                *(fat +  ((unsigned char) correctClusterComb[incred-1] +
                                                          (np * (my_disk->BPB_BytsPerSec * my_disk->BPB_FATSz32))/4))
                                                        = (unsigned char) correctClusterComb[incred];
//                                                printf("after the fat is %d\n", *(fat + iidex));
                                                incred++;
                                            }
                                            //printf("correct Cluster is %d\n", correctClusterComb[incred-2]);
//                                            printf("before the fat is %d\n",*(fat + (unsigned char) correctClusterComb[incred-2] +
//                                                                              np * (my_disk->BPB_BytsPerSec * my_disk->BPB_FATSz32)/4));
                                            *(fat + (unsigned char) correctClusterComb[incred-2] +
                                                    (np * (my_disk->BPB_BytsPerSec * my_disk->BPB_FATSz32))/4) = 0xfffffff;
//                                            printf("after the fat is %d\n",*(fat + (unsigned char) correctClusterComb[incred-2] +
//                                                                              np * (my_disk->BPB_BytsPerSec * my_disk->BPB_FATSz32)/4));
                                        }
                                        printf("%s: successfully recovered with SHA-1\n", file);
                                        end_milestone = true;
                                        break;
                                    }
                                kix++;
                            }


                        }

                        else{
                            unsigned int offset = 0;
                            unsigned int last_content_clus_quotient = (my_dirEntry->DIR_FileSize) / (my_disk->BPB_BytsPerSec * my_disk->BPB_SecPerClus);
                            unsigned int last_content_clus_reminder = (my_dirEntry->DIR_FileSize) % (my_disk->BPB_BytsPerSec * my_disk->BPB_SecPerClus);
                            unsigned char* buffer = malloc((my_dirEntry->DIR_FileSize+1) * sizeof (unsigned char));
                            for(unsigned int idx = 0; idx < my_dirEntry->DIR_FileSize; idx += (my_disk->BPB_BytsPerSec * my_disk->BPB_SecPerClus)){
                                unsigned char* start_of_cluster = (unsigned char *) (addr + begin_data_area + (((my_dirEntry->DIR_FstClusHI <<16) + my_dirEntry->DIR_FstClusLO) - 2+offset)
                                                                                                              * (my_disk->BPB_BytsPerSec * my_disk->BPB_SecPerClus));
                                if (offset == last_content_clus_quotient){
//                                    unsigned char buffer[last_content_clus_reminder];
                                    memcpy(buffer+idx, start_of_cluster, last_content_clus_reminder);
                                }
                                else{
//                                    unsigned char buffer[(my_disk->BPB_BytsPerSec * my_disk->BPB_SecPerClus)];
                                    memcpy(buffer+idx, start_of_cluster, (my_disk->BPB_BytsPerSec * my_disk->BPB_SecPerClus));
                                    //printf("offset is % d buffer is: %s \n", offset, buffer);
//                                    SHA1_Update(&sha_ctx, &buffer,(my_disk->BPB_BytsPerSec * my_disk->BPB_SecPerClus));
                                }

                                offset++;
                            }
                            //SHA1_Final(hash, &sha_ctx);
                            SHA1((const unsigned char*)buffer, my_dirEntry->DIR_FileSize, hash);
                            for(int i = 0; i<SHA_DIGEST_LENGTH; i++) {
                                sprintf((char*)&hash_40[i*2], "%02x", hash[i]);
                            }
                            //printf("Hash: %s\n", hash_40);
                            if (strcmp(hash_40, (char *)sha_input) == 0){
                                my_dirEntry->DIR_Name[0] = file[0];
                                for (int n = 0; n <my_disk->BPB_NumFATs; n++){
                                    unsigned int incred = 1;
                                    unsigned char start_of_fat = ((my_dirEntry->DIR_FstClusHI << 16) + my_dirEntry->DIR_FstClusLO) + n*(my_disk->BPB_BytsPerSec*my_disk->BPB_FATSz32);
                                    for(unsigned int idx = 0; idx < my_dirEntry->DIR_FileSize; idx += (my_disk->BPB_BytsPerSec * my_disk->BPB_SecPerClus)){
                                        *(fat + (incred -1 + start_of_fat))
                                                = ((my_dirEntry->DIR_FstClusHI << 16) + my_dirEntry->DIR_FstClusLO) + incred;
                                        incred ++;
                                    }
                                    *(fat + (incred -1 + start_of_fat)) = 0xfffffff;
                                }
                                printf("%s: successfully recovered with SHA-1\n", file);
                                end_milestone = true;
                                break;
                            }

                        }
                    }
                }
                num_of_dir_per_clus_index += 32;
            }
            fat_cluster = *(fat+fat_cluster);
        }
        if ((num_of_found_file == 0) || (end_milestone == false)){
            printf("%s: file not found\n", file);
        }


    }



}

