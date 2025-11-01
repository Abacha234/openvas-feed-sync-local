# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892369");
  script_cve_id("CVE-2017-18258", "CVE-2017-8872", "CVE-2018-14404", "CVE-2018-14567", "CVE-2019-19956", "CVE-2019-20388", "CVE-2020-24977", "CVE-2020-7595");
  script_tag(name:"creation_date", value:"2020-09-10 07:28:40 +0000 (Thu, 10 Sep 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-06 06:15:00 +0000 (Tue, 06 Jul 2021)");

  script_name("Debian: Security Advisory (DLA-2369)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2369");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2369");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/libxml2");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libxml2' package(s) announced via the DLA-2369 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security vulnerabilities were corrected in libxml2, the GNOME XML library.

CVE-2017-8872

Global buffer-overflow in the htmlParseTryOrFinish function.

CVE-2017-18258

The xz_head function in libxml2 allows remote attackers to cause a denial of service (memory consumption) via a crafted LZMA file, because the decoder functionality does not restrict memory usage to what is required for a legitimate file.

CVE-2018-14404

A NULL pointer dereference vulnerability exists in the xpath.c:xmlXPathCompOpEval() function of libxml2 when parsing an invalid XPath expression in the XPATH_OP_AND or XPATH_OP_OR case. Applications processing untrusted XSL format inputs may be vulnerable to a denial of service attack.

CVE-2018-14567

If the option --with-lzma is used, allows remote attackers to cause a denial of service (infinite loop) via a crafted XML file.

CVE-2019-19956

The xmlParseBalancedChunkMemoryRecover function has a memory leak related to newDoc->oldNs.

CVE-2019-20388

A memory leak was found in the xmlSchemaValidateStream function of libxml2. Applications that use this library may be vulnerable to memory not being freed leading to a denial of service.

CVE-2020-7595

Infinite loop in xmlStringLenDecodeEntities can cause a denial of service.

CVE-2020-24977

Out-of-bounds read restricted to xmllint --htmlout.

For Debian 9 stretch, these problems have been fixed in version 2.9.4+dfsg1-2.2+deb9u3.

We recommend that you upgrade your libxml2 packages.

For the detailed security status of libxml2 please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'libxml2' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);