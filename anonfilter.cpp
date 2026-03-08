/*
 * Copyright (C) 2026 dannyAAM
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 */

#include <znc/znc.h>
#include <znc/IRCNetwork.h>
#include <znc/IRCSock.h>
#include <znc/User.h>

// hope ZNC never change this...?
#define ZNC_DEF_REALNAME "ZNC - https://znc.in"

static const VCString AllowedInbound = {
    // "NOTICE", // can contain CTCP
    "PING",
    //"PONG",
    "MODE",
    "JOIN",
    "NICK",
    "QUIT",
    "PART",
    "WALLOPS",
    "ERROR",
    "KICK",
    "H", // "hide operator status" (after kicking an op)
    "TOPIC",
    "AUTHENTICATE", // SASL, also requires CAP below
    // http://tools.ietf.org/html/draft-mitchell-irc-capabilities-01
    "CAP",
    "PROTOCTL",
    "AWAY",
    "ACCOUNT",  // https://ircv3.net/specs/extensions/account-notify
    "CHGHOST"   // https://ircv3.net/specs/extensions/chghost
};

static const VCString AllowedOutbound = {
    // Commands that regular users might use
    "ACCEPT", // Inspircd's m_callerid.so module
    "ADMIN",
    "AUTHENTICATE", // SASL, also requires CAP below
    "AWAY",    // should be harmless
    "CAP",     // http://tools.ietf.org/html/draft-mitchell-irc-capabilities-01
    "COMMANDS",
    "CYCLE",
    "DCCALLOW",
    "DEVOICE",
    "FPART",
    "HELPME", "HELPOP",  // helpop is what unrealircd uses by default
    "INVITE",
    "ISON",    // jIRCii uses this for a ping (response is 303)
    "JOIN",
    "KICK",
    "KNOCK",
    "LINKS",
    "LIST",
    "LUSERS",
    "MAP", // seems safe enough, the ircd should protect themselves though
    "MODE",
    "MOTD",
    "NAMES",
    "NICK",
    // "NOTICE", // can contain CTCP
    "OPER",
    // "PART", // replace with filtered PART to hide client part messages
    "PASS",
    // "PING",
    "PONG",
    "PROTOCTL",
    // "QUIT", // replace with a filtered QUIT to hide client quit messages
    "RULES",
    "SETNAME",
    "SILENCE",
    "SSLINFO",
    "STATS",
    "TBAN",
    "TITLE",
    "TOPIC",
    "UNINVITE",
    "USERHOST",
    "USERS", // Ticket 1249
    "VHOST",
    "VHOST",
    "WATCH",
    "WHO",
    "WHOIS",
    "WHOWAS",
    // the next few are default aliases on unreal (+ anope)
    "BOTSERV", "BS",
    "CHANSERV", "CS",
    "HELPSERV",
    "HOSTSERV", "HS",
    "MEMOSERV", "MS",
    "NICKSERV", "NS",
    "OPERSERV", "OS",
    "STATSERV",
    // IRCop commands
    "ADCHAT",
    "ADDMOTD",
    "ADDOMOTD",
    "CBAN",
    "CHATOPS",
    "CHECK",
    "CHGHOST",
    "CHGIDENT",
    "CHGNAME",
    "CLOSE",
    "DCCDENY",
    "DIE",
    "ELINE",
    "FILTER",
    "GLINE",
    "GLOBOPS",
    "GZLINE",
    "HTM", // "High Traffic Mode"
    "JUMPSERVER",
    "KILL",
    "KLINE",
    "LOADMODULE",
    "LOCKSERV",
    "LOCOPS",
    "MKPASSWD",
    "NACHAT",
    "NICKLOCK",
    "NICKUNLOCK",
    "OLINE",
    "OPERMOTD",
    "REHASH",
    "RELOADMODULE",
    "RESTART",
    "RLINE",
    "SAJOIN",
    "SAKICK",
    "SAMODE",
    "SANICK",
    "SAPART",
    "SATOPIC",
    "SDESC",
    "SETHOST",
    "SETIDENT",
    "SHUN",
    "SPAMFILTER",
    "SQUIT",
    "TEMPSHUN",
    "TLINE",
    "UNDCCDENY",
    "UNLOCKSERV",
    "WALLOPS",
    "ZLINE"
};

class AnonFilterPongReplyTimer : public CCron {
    CIRCNetwork *m_pNet;
    CString m_payload;

  public:
    AnonFilterPongReplyTimer(CIRCNetwork* pNet, CString payload) : m_pNet(pNet), m_payload(payload) {
        StartMaxCycles(0.01, 1);
    }
    AnonFilterPongReplyTimer(const AnonFilterPongReplyTimer&) = delete;
    AnonFilterPongReplyTimer& operator=(const AnonFilterPongReplyTimer&) = delete;
    void RunJob() override {
        // according to IRCFilter.java... some client expect special PONG...?
        // I'm lazy so if it breaks, just let it break
        // if this will affect you, PR is welcome
        CString reply(":irc.znc.in PONG irc.znc.in " + m_payload);
        CIRCSock *pSock = m_pNet->GetIRCSock();
        if (pSock) pSock->ReadLine(reply);
    }
};

class AnonFilterMod : public CModule {
  protected:
    bool m_bAllowI2PDCC;
  public:
    MODCONSTRUCTOR(AnonFilterMod) {
        AddHelpCommand();
    }

    ~AnonFilterMod() override { }

    bool OnBoot() override {
        return true;
    }

    bool OnLoad(const CString& sArgs, CString& sMessage) override {
        if (sArgs.Equals("i2pdcc")) {
            m_bAllowI2PDCC = true;
        }
        return true;
    }

    EModRet filterI2PDCCAddr(CCTCPMessage& msg) {
        CString sL = msg.GetText();
        CString sType = sL.Token(1, false, " ", false, "\"", "\"", true);
        if (sType.Equals("RESUME") || sType.Equals("ACCEPT")) {
            // no IP, pass through
            return CONTINUE;
        } else if (sType.Equals("CHAT") || sType.Equals("SEND")) {
            CString ip = sL.Token(3, false, " ", false, "\"", "\"", true);
            if (ip.EndsWith(".b32.i2p")) {
                return CONTINUE;
            } else {
                return HALT;
            }
        }
        return HALT;
    }

    /**
     *  DCC CHAT chat xxx.b32.i2p i2p-port        -> DCC CHAT chat IP port
     *  DCC SEND file xxx.b32.i2p i2p-port length -> DCC SEND file IP port length
     *  DCC RESUME file i2p-port offset           -> DCC RESUME file port offset
     *  DCC ACCEPT file i2p-port offset           -> DCC ACCEPT file port offset
     *  DCC xxx                                   -> null
     */
    EModRet filterI2PDCCIn(CCTCPMessage& msg) {
        // no i2p dcc proxy yet (forever?)
        return filterI2PDCCAddr(msg);
    }

    /**
     *  DCC CHAT chat IP port        -> DCC CHAT chat xxx.b32.i2p i2p-port
     *  DCC SEND file IP port length -> DCC SEND file xxx.b32.i2p i2p-port length
     *  DCC RESUME file port offset  -> DCC RESUME file i2p-port offset
     *  DCC ACCEPT file port offset  -> DCC ACCEPT file i2p-port offset
     *  DCC xxx                      -> null
     */
    EModRet filterI2PDCCOut(CCTCPMessage& msg) {
        // no i2p dcc proxy yet (forever?)
        return filterI2PDCCAddr(msg);
    }

    EModRet OnRawMessage(CMessage& msg) override { // inbound
        switch (msg.GetType()) {
            // allow numerical responses
            case CMessage::Type::Numeric:
                return CONTINUE;
            case CMessage::Type::Pong:
                // normally ping won't pass through znc
                // the only exception is probably route_replies
                // which we hijack it then throw back with readline immediately
                // which will be caught here, thus we don't really need to process it
                return HALTCORE;
            // handle CTCP, ACTION is separate type on ZNC
            case CMessage::Type::CTCP: {
                CCTCPMessage ctcpMsg = msg.As<CCTCPMessage>();
                if (m_bAllowI2PDCC && ctcpMsg.GetText().StartsWith("DCC ")) {
                    return filterI2PDCCIn(ctcpMsg);
                }
                // block all other CTCP
                return HALT;
            }
            // try to filter out legacy CTCP
            case CMessage::Type::Notice:
            case CMessage::Type::Text:
                if (msg.GetParam(1).find(0x1) != std::string::npos) {
                    // I2P will try to handle legacy CTCP
                    // but ZNC doesn't handle it so we just drop it to be safe
                    // (meh, it's not cuz I'm lazy, really)
                    return HALT;
                }
                return CONTINUE;
        }
        // for the rest, check against allow list
        if (std::find(AllowedInbound.begin(), AllowedInbound.end(), msg.GetCommand()) !=
                AllowedInbound.end()) {
            return CONTINUE;
        } else {
            return HALT;
        }
    }

    EModRet OnSendToIRCMessage(CMessage& msg) override { // outbound
        switch (msg.GetType()) {
            case CMessage::Type::Ping: {
                // normally, we should never get ping from client
                // the only excpetion is probably route_replies
                // which we will hijack directly to make things easier
                CString payload = msg.GetParamsColon(0);
                if (payload.Equals(":ZNC")) {
                    // PING from znc, let it through
                    // well, hope no client will ping with ZNC as param
                    // (another znc...? but znc doesn't really care about reply)
                    return CONTINUE;
                } else {
                    // need some delay or things will go crazy
                    auto pTimer = new AnonFilterPongReplyTimer(msg.GetNetwork(), payload);
                    CZNC::Get().GetManager().AddCron(pTimer);
                    return HALT;
                }
            }
            // handle CTCP, ACTION is separate type on ZNC
            case CMessage::Type::CTCP: {
                CCTCPMessage ctcpMsg = msg.As<CCTCPMessage>();
                if (m_bAllowI2PDCC && ctcpMsg.GetText().StartsWith("DCC ")) {
                    return filterI2PDCCOut(ctcpMsg);
                }
                // block all other CTCP
                return HALT;
            }
            // mIRC sends "NOTICE user :DCC Send file (IP)"
            // in addition to the CTCP version
            // otherwise, pass to next case for legacy CTCP
            case CMessage::Type::Notice:
                // it seems mIRC also sends normal ctcp dcc
                // thus, we should be able to discard this safely
                // hence... we just discard it, it's easier
                if (msg.GetParam(1).StartsWith("DCC ")) {
                    return HALT;
                }
                // * don't return if not handled above
            // try to filter out legacy CTCP
            case CMessage::Type::Text:
                if (msg.GetParam(1).find(0x1) != std::string::npos) {
                    // I2P will try to handle legacy CTCP
                    // but ZNC doesn't handle it so we just drop it to be safe
                    // (meh, it's not cuz I'm lazy, really)
                    return HALT;
                }
                return CONTINUE;
            // maybe you can just change part/quit message...
            // but we just replace like what i2p irc do
            case CMessage::Type::Part:
            case CMessage::Type::Quit:
                msg.SetParam(1, "leaving");
                return CONTINUE;
            case CMessage::Type::Unknown:
                // alter user command like I2P to avoid leaking usage of ZNC
                if (msg.GetCommand() == "USER") {
                    msg.SetParam(1, "hostname");
                    msg.SetParam(2, "localhost");
                    CString realname = msg.GetNetwork()->GetRealName();
                    msg.SetParam(3, realname.Equals(ZNC_DEF_REALNAME) ? "realname" : realname);
                    return CONTINUE;
                }
        }
        // for the rest, check against allow list
        if (std::find(AllowedOutbound.begin(), AllowedOutbound.end(), msg.GetCommand()) !=
                AllowedOutbound.end()) {
            return CONTINUE;
        } else {
            return HALT;
        }
    }
};

template <>
void TModInfo<AnonFilterMod>(CModInfo& Info) {
    //Info.SetWikiPage("anonfilter");
    Info.SetHasArgs(true);
    Info.SetArgsHelpText(Info.t_s(
        "Put i2pdcc to allow DCC with i2p addresses"));
}

NETWORKMODULEDEFS(
    AnonFilterMod,
    "Plugin that implements IRCFilter from I2PTunnel from I2P Project.")
