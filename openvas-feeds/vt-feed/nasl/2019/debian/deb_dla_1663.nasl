# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891663");
  script_cve_id("CVE-2016-0772", "CVE-2016-5636", "CVE-2016-5699", "CVE-2018-20406", "CVE-2019-5010");
  script_tag(name:"creation_date", value:"2019-02-06 23:00:00 +0000 (Wed, 06 Feb 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-09 11:29:00 +0000 (Sat, 09 Feb 2019)");

  script_name("Debian: Security Advisory (DLA-1663)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1663");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/dla-1663");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'python3.4' package(s) announced via the DLA-1663 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This DLA fixes a problem parsing x509 certificates, an pickle integer overflow, and some other minor issues:

CVE-2016-0772

The smtplib library in CPython does not return an error when StartTLS fails, which might allow man-in-the-middle attackers to bypass the TLS protections by leveraging a network position between the client and the registry to block the StartTLS command, aka a 'StartTLS stripping attack.'

CVE-2016-5636

Integer overflow in the get_data function in zipimport.c in CPython allows remote attackers to have unspecified impact via a negative data size value, which triggers a heap-based buffer overflow.

CVE-2016-5699

CRLF injection vulnerability in the HTTPConnection.putheader function in urllib2 and urllib in CPython allows remote attackers to inject arbitrary HTTP headers via CRLF sequences in a URL.

CVE-2018-20406

Modules/_pickle.c has an integer overflow via a large LONG_BINPUT value that is mishandled during a resize to twice the size attempt. This issue might cause memory exhaustion, but is only relevant if the pickle format is used for serializing tens or hundreds of gigabytes of data.

CVE-2019-5010

NULL pointer dereference using a specially crafted X509 certificate.

For Debian 8 Jessie, these problems have been fixed in version 3.4.2-1+deb8u2.

We recommend that you upgrade your python3.4 packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'python3.4' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);