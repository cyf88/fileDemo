//
// Created by cyf on 2024/2/28.
//
#include "TriPsReader.h"
#include <iostream>
#include "mongoose.h"
#include "nlohmann/json.hpp"
#include <map>
#include <vector>

using json = nlohmann::json;

std::vector<std::map<std::string, std::string>> failframes;

static const char *s_http_addr = "http://0.0.0.0:8000";    // HTTP port
static const char *s_https_addr = "https://0.0.0.0:8443";  // HTTPS port
static const char *s_root_dir = ".";




int signSucNum = 0;
int signFailNum = 0;
std::string g_streamId;

int sign_notify(unsigned int uiChan, ULONG ulRetCode, char* streamId, char* time) {
    std::cout << "sign_notify uiChan: " << uiChan << " RetCode: "
        << ulRetCode << "streamId: "<< streamId << std::endl;
    g_streamId = std::string(streamId).substr(0, 19);
    if (ulRetCode == 0) {
        signSucNum++;
        std::cout << "signSucNum: " << signSucNum << std::endl;
    } else {
        signFailNum++;
        std::map<std::string, std::string> failmap;
        failmap.emplace("offset", std::to_string(signSucNum + signFailNum));
        failmap.emplace("time", time);
        failframes.push_back(failmap);
    }
    return 0;
}


static void ev_handler(struct mg_connection *c, int ev, void *ev_data) {

    if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message* hm = (struct mg_http_message*)ev_data;
        if (mg_http_match_uri(hm, "/sign/start")) {
            std::string streamFile =  mg_json_get_str(hm->body, "$.streamFile");
            std::string certFile = mg_json_get_str(hm->body, "$.certFile");
            std::cout << "streamFile: " << streamFile << std::endl;
            std::cout << "certFile: " << certFile << std::endl;
            signSucNum = 0;
            signFailNum = 0;
            failframes.clear();
            auto triPsReader = new TriPsReader(streamFile.c_str(),
                                               certFile.c_str(),
                                               reinterpret_cast<FUNC_SUT_SIGNVERIFYNOTIFY>(sign_notify));

            if (triPsReader->init()) {
                triPsReader->doRead();
                json jsonRes;
                jsonRes["signSuc"] = signSucNum;
                jsonRes["signFail"] = signFailNum;
                jsonRes["streamId"] = g_streamId;
                json j_vec(failframes);
                jsonRes["failFrames"] = j_vec;
                mg_http_reply(c, 200, "Content-Type: application/json\r\n", jsonRes.dump().c_str());

            } else {
                mg_http_reply(c, 500, "Content-Type: application/json\r\n", "{\"result\":%s}", "error");
            }

            delete triPsReader;

        }

    }
}

int main() {


    struct mg_mgr mgr;                            // Event manager
    mg_log_set(MG_LL_DEBUG);                      // Set log level
    mg_mgr_init(&mgr);                            // Initialise event manager
    mg_http_listen(&mgr, s_http_addr, ev_handler, NULL);  // Create HTTP listener
    for (;;) mg_mgr_poll(&mgr, 1000);                    // Infinite event loop
    mg_mgr_free(&mgr);
    return 0;


//    auto triPsReader = new TriPsReader("/home/cyf/223.ps",
//                                       "/home/cyf/13100000001181000223_sign.cer",
//                                       reinterpret_cast<FUNC_SUT_SIGNVERIFYNOTIFY>(sign_notify));
//
//   // auto triPsReader = new TriPsReader("C:\\Users\\cyf\\Desktop\\triplayer-ukey\\src.ps",
//   //                                    "C:\\Users\\cyf\\Desktop\\triplayer-ukey\\13100000001181000223_sign.cer");
//
//    triPsReader->init();
//    triPsReader->doRead();
//
//    delete triPsReader;
//    std::cout << "work done: " << std::endl;

}