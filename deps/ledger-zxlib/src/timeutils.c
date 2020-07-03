/*******************************************************************************
*   (c) 2018 Zondax GmbH
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/
#include "zxmacros.h"
#include "timeutils.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

const uint8_t monthDays[] = {
        31,
        28,
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31
};

const uint32_t yearLookup[] = {
        0,
        365,
        730,
        1096,
        1461,
        1826,
        2191,
        2557,
        2922,
        3287,
        3652,
        4018,
        4383,
        4748,
        5113,
        5479,
        5844,
        6209,
        6574,
        6940,
        7305,
        7670,
        8035,
        8401,
        8766,
        9131,
        9496,
        9862,
        10227,
        10592,
        10957,
        11323,
        11688,
        12053,
        12418,
        12783,
        13149,
        13514,
        13879,
        14244,
        14610,
        14975,
        15340,
        15705,
        16071,
        16436,
        16801,
        17166,
        17532,
        17897,
        18262,
        18627,
        18993,
        19358,
        19723,
        20088,
        20454,
        20819,
        21184,
        21549,
        21915,
        22280,
        22645,
        23010,
        23376,
        23741,
        24106,
        24471,
        24836,
        25202,
        25567,
        25932,
        26297,
        26663,
        27028,
        27393,
        27758,
        28124,
        28489,
        28854,
        29219,
        29585,
        29950,
        30315,
        30680,
        31046,
        31411,
        31776,
        32141,
        32507,
        32872,
        33237,
        33602,
        33968,
        34333,
        34698,
        35063,
        35429,
        35794,
        36159,
        36524,
        36889,
        37255,
        37620,
        37985,
        38350,
        38716,
        39081,
        39446,
        39811,
        40177,
        40542,
        40907,
        41272,
        41638,
        42003,
        42368,
        42733,
        43099,
        43464,
        43829,
        44194,
        44560,
        44925,
        45290,
        45655,
        46021,
        46386,
        46751,
        47116,
        47482,
        47847,
        48212,
        48577,
        48942,
        49308,
        49673,
        50038,
        50403,
        50769,
        51134,
        51499,
        51864,
        52230,
        52595,
        52960,
        53325,
        53691,
        54056,
        54421,
        54786,
        55152,
        55517,
        55882,
        56247,
        56613,
        56978,
        57343,
        57708,
        58074,
        58439,
        58804,
        59169,
        59535,
        59900,
        60265,
        60630,
        60995,
        61361,
        61726,
        62091,
        62456,
        62822,
        63187,
        63552,
        63917,
        64283,
        64648,
        65013,
        65378,
        65744,
        66109,
        66474,
        66839,
        67205,
        67570,
        67935,
        68300,
        68666,
        69031,
        69396,
        69761,
        70127,
        70492,
        70857,
        71222,
        71588,
        71953,
        72318,
        72683
};

// ARM does not implement gmtime. This is a simple alternative implementation
// based on section 4.16
// https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap04.html
void printTime(char *out, uint16_t outLen, uint64_t t) {
    uint8_t tm_sec = 0;
    uint8_t tm_min = 0;
    uint8_t tm_hour = 0;
    uint8_t tm_day = 0;
    uint8_t tm_mon = 0;
    uint16_t tm_year = 0;

    tm_sec = t % 60;
    t -= tm_sec;
    t /= 60;

    tm_min = t % 60;
    t -= tm_min;
    t /= 60;

    tm_hour = t % 24;
    t -= tm_hour;
    t /= 24;

    // Look up tm_year
    tm_year = 0;
    while (tm_year < 200 && yearLookup[tm_year] < t) tm_year++;
    tm_year--;
    tm_day = t - yearLookup[tm_year] + 1;
    tm_year = 1970 + tm_year;

    // Get day/month
    uint8_t leap = (tm_year % 4 == 0 && (tm_year % 100 != 0 || tm_year % 400 == 0) ? 1 : 0);

    for (tm_mon = 0; tm_mon < 12; tm_mon++) {
        uint8_t tmp = monthDays[tm_mon];
        tmp += (tm_mon == 1 ? leap : 0);
        if (tm_day <= tmp) {
            break;
        }
        tm_day -= tmp;
    }
    tm_mon++;

    char *monthName;
    switch (tm_mon) {
        case 1:
            monthName = "Jan";
            break;
        case 2:
            monthName = "Feb";
            break;
        case 3:
            monthName = "Mar";
            break;
        case 4:
            monthName = "Apr";
            break;
        case 5:
            monthName = "May";
            break;
        case 6:
            monthName = "Jun";
            break;
        case 7:
            monthName = "Jul";
            break;
        case 8:
            monthName = "Aug";
            break;
        case 9:
            monthName = "Sep";
            break;
        case 10:
            monthName = "Oct";
            break;
        case 11:
            monthName = "Nov";
            break;
        case 12:
            monthName = "Dec";
            break;
        default:
            monthName = "ERR";
    }

    // YYYYmmdd HH:MM:SS
    snprintf(out, outLen, "%02d%s%04d %02d:%02d:%02d",
             tm_day,
             monthName,
             tm_year,
             tm_hour, tm_min, tm_sec
    );
}

#ifdef __cplusplus
}
#endif
