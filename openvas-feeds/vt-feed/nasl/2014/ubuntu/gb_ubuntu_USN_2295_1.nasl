# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841914");
  script_cve_id("CVE-2014-1544", "CVE-2014-1547", "CVE-2014-1548", "CVE-2014-1549", "CVE-2014-1550", "CVE-2014-1552", "CVE-2014-1555", "CVE-2014-1556", "CVE-2014-1557", "CVE-2014-1558", "CVE-2014-1559", "CVE-2014-1560", "CVE-2014-1561");
  script_tag(name:"creation_date", value:"2014-07-28 11:10:56 +0000 (Mon, 28 Jul 2014)");
  script_version("2024-06-26T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-06-26 05:05:39 +0000 (Wed, 26 Jun 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2295-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2295-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2295-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1342311");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-2295-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Christian Holler, David Keeler, Byron Campen, Gary Kwong, Jesse Ruderman,
Andrew McCreight, Alon Zakai, Bobby Holley, Jonathan Watt, Shu-yu Guo,
Steve Fink, Terrence Cole, Gijs Kruitbosch and Catalin Badea discovered
multiple memory safety issues in Firefox. If a user were tricked in to
opening a specially crafted website, an attacker could potentially exploit
these to cause a denial of service via application crash, or execute
arbitrary code with the privileges of the user invoking Firefox.
(CVE-2014-1547, CVE-2014-1548)

Atte Kettunen discovered a buffer overflow when interacting with WebAudio
buffers. An attacker could potentially exploit this to cause a denial of
service via application crash or execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2014-1549)

Atte Kettunen discovered a use-after-free in WebAudio. An attacker could
potentially exploit this to cause a denial of service via application
crash or execute arbitrary code with the privileges of the user invoking
Firefox. (CVE-2014-1550)

David Chan and Gijs Kruitbosch discovered that web content could spoof
UI customization events in some circumstances, resulting in a limited
ability to move UI icons. (CVE-2014-1561)

Jethro Beekman discovered a use-after-free when the FireOnStateChange
event is triggered in some circumstances. An attacker could potentially
exploit this to cause a denial of service via application crash or
execute arbitrary code with the privileges of the user invoking Firefox.
(CVE-2014-1555)

Patrick Cozzi discovered a crash when using the Cesium JS library to
generate WebGL content. An attacker could potentially exploit this to
execute arbitrary code with the privileges of the user invoking Firefox.
(CVE-2014-1556)

Tyson Smith and Jesse Schwartzentruber discovered a use-after-free in
CERT_DestroyCertificate. An attacker could potentially exploit this to
cause a denial of service via application crash or execute arbitrary
code with the privileges of the user invoking Firefox. (CVE-2014-1544)

A crash was discovered in Skia when scaling an image, if the scaling
operation takes too long. An attacker could potentially exploit this to
execute arbitrary code with the privileges of the user invoking Firefox.
(CVE-2014-1557)

Christian Holler discovered several issues when parsing certificates
with non-standard character encoding, resulting in the inability to
use valid SSL certificates in some circumstances. (CVE-2014-1558,
CVE-2014-1559, CVE-2014-1560)

Boris Zbarsky discovered that network redirects could cause an iframe
to escape the confinements defined by its sandbox attribute in
some circumstances. An attacker could potentially exploit this to
conduct cross-site scripting attacks. (CVE-2014-1552)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 12.04, Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
