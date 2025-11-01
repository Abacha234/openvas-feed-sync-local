# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886294");
  script_version("2025-03-11T05:38:16+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"creation_date", value:"2024-03-25 09:38:33 +0000 (Mon, 25 Mar 2024)");
  script_name("Fedora: Security Advisory for baresip (FEDORA-2024-e34efa1300)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-e34efa1300");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/MHFSYVLI67MXSWJCC3I2XTKIGVJV22EQ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'baresip'
  package(s) announced via the FEDORA-2024-e34efa1300 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A modular SIP user-agent with support for audio and video, and many IETF
standards such as SIP, SDP, RTP/RTCP and STUN/TURN/ICE for both, IPv4 and
IPv6.

Additional modules provide support for audio codecs like Codec2, G.711,
G.722, G.726, GSM, L16, MPA and Opus, audio drivers like ALSA, GStreamer,
JACK Audio Connection Kit, Portaudio, and PulseAudio, video codecs like
AV1, VP8 or VP9, video sources like Video4Linux, video outputs like SDL2
or X11, NAT traversal via STUN, TURN, ICE, and NAT-PMP, media encryption
via TLS, SRTP or DTLS-SRTP, management features like embedded web-server
with HTTP interface, command-line console and interface, and MQTT.");

  script_tag(name:"affected", value:"'baresip' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
