# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702950");
  script_cve_id("CVE-2014-0195", "CVE-2014-0221", "CVE-2014-0224", "CVE-2014-3470");
  script_tag(name:"creation_date", value:"2014-06-04 22:00:00 +0000 (Wed, 04 Jun 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-28 16:40:00 +0000 (Tue, 28 Jul 2020)");

  script_name("Debian: Security Advisory (DSA-2950)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2950");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2950");
  script_xref(name:"URL", value:"http://www.openssl.org/news/secadv_20140605.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openssl' package(s) announced via the DSA-2950 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in OpenSSL:

CVE-2014-0195

Jueri Aedla discovered that a buffer overflow in processing DTLS fragments could lead to the execution of arbitrary code or denial of service.

CVE-2014-0221

Imre Rad discovered the processing of DTLS hello packets is susceptible to denial of service.

CVE-2014-0224

KIKUCHI Masashi discovered that carefully crafted handshakes can force the use of weak keys, resulting in potential man-in-the-middle attacks.

CVE-2014-3470

Felix Groebert and Ivan Fratric discovered that the implementation of anonymous ECDH ciphersuites is suspectible to denial of service.

Additional information can be found at [link moved to references]

For the stable distribution (wheezy), these problems have been fixed in version 1.0.1e-2+deb7u10. All applications linked to openssl need to be restarted. You can use the tool checkrestart from the package debian-goodies to detect affected programs or reboot your system. There's also a forthcoming security update for the Linux kernel later the day (CVE-2014-3153), so you need to reboot anyway. Perfect timing, isn't it?

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your openssl packages.");

  script_tag(name:"affected", value:"'openssl' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);