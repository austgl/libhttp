#pragma once

//http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html#sec10
//1xx 无body
#define EVHTP_RES_100          100
#define EVHTP_RES_CONTINUE     100
#define EVHTP_RES_SWITCH_PROTO 101
#define EVHTP_RES_PROCESSING   102
#define EVHTP_RES_URI_TOOLONG  122

//2xx
//This class of status code indicates that the client's request was successfully received, understood, and accepted
#define EVHTP_RES_200          200
#define EVHTP_RES_CREATED      201
#define EVHTP_RES_ACCEPTED     202
#define EVHTP_RES_NAUTHINFO    203
#define EVHTP_RES_NOCONTENT    204
#define EVHTP_RES_RSTCONTENT   205
#define EVHTP_RES_PARTIAL      206
#define EVHTP_RES_MSTATUS      207
#define EVHTP_RES_IMUSED       226

//3xx
#define EVHTP_RES_300          300
#define EVHTP_RES_MCHOICE      300
#define EVHTP_RES_MOVEDPERM    301
#define EVHTP_RES_FOUND        302
#define EVHTP_RES_SEEOTHER     303
#define EVHTP_RES_NOTMOD       304
#define EVHTP_RES_USEPROXY     305
#define EVHTP_RES_SWITCHPROXY  306
#define EVHTP_RES_TMPREDIR     307

//4xx
//The 4xx class of status code is intended for cases in which the client seems to have erred
#define EVHTP_RES_400          400
#define EVHTP_RES_BADREQ       400
#define EVHTP_RES_UNAUTH       401
#define EVHTP_RES_PAYREQ       402
#define EVHTP_RES_FORBIDDEN    403
#define EVHTP_RES_NOTFOUND     404
#define EVHTP_RES_METHNALLOWED 405
#define EVHTP_RES_NACCEPTABLE  406
#define EVHTP_RES_PROXYAUTHREQ 407
#define EVHTP_RES_TIMEOUT      408
#define EVHTP_RES_CONFLICT     409
#define EVHTP_RES_GONE         410
#define EVHTP_RES_LENREQ       411
#define EVHTP_RES_PRECONDFAIL  412
#define EVHTP_RES_ENTOOLARGE   413
#define EVHTP_RES_URITOOLARGE  414
#define EVHTP_RES_UNSUPPORTED  415
#define EVHTP_RES_RANGENOTSC   416
#define EVHTP_RES_EXPECTFAIL   417
#define EVHTP_RES_IAMATEAPOT   418

//The server encountered an unexpected condition which prevented it from fulfilling the request.
#define EVHTP_RES_500          500
#define EVHTP_RES_SERVERR      500
#define EVHTP_RES_NOTIMPL      501
#define EVHTP_RES_BADGATEWAY   502
#define EVHTP_RES_SERVUNAVAIL  503
#define EVHTP_RES_GWTIMEOUT    504
#define EVHTP_RES_VERNSUPPORT  505
#define EVHTP_RES_BWEXEED      509
