# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892735");
  script_cve_id("CVE-2018-14662", "CVE-2018-16846", "CVE-2020-10753", "CVE-2020-1760", "CVE-2021-3524");
  script_tag(name:"creation_date", value:"2021-08-13 09:50:27 +0000 (Fri, 13 Aug 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-25 16:49:00 +0000 (Tue, 25 May 2021)");

  script_name("Debian: Security Advisory (DLA-2735)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2735");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/dla-2735");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/ceph");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ceph' package(s) announced via the DLA-2735 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Ceph, a distributed storage and file system.

CVE-2018-14662

Authenticated ceph users with read only permissions could steal dm-crypt encryption keys used in ceph disk encryption.

CVE-2018-16846

Authenticated ceph RGW users can cause a denial of service against OMAPs holding bucket indices.

CVE-2020-10753

A flaw was found in the Red Hat Ceph Storage RadosGW (Ceph Object Gateway). The vulnerability is related to the injection of HTTP headers via a CORS ExposeHeader tag. The newline character in the ExposeHeader tag in the CORS configuration file generates a header injection in the response when the CORS request is made.

CVE-2020-1760

A flaw was found in the Ceph Object Gateway, where it supports request sent by an anonymous user in Amazon S3. This flaw could lead to potential XSS attacks due to the lack of proper neutralization of untrusted input.

CVE-2021-3524

A flaw was found in the Red Hat Ceph Storage RadosGW (Ceph Object Gateway) The vulnerability is related to the injection of HTTP headers via a CORS ExposeHeader tag. The newline character in the ExposeHeader tag in the CORS configuration file generates a header injection in the response when the CORS request is made. In addition, the prior bug fix for CVE-2020 10753 did not account for the use of r as a header separator, thus a new flaw has been created.

For Debian 9 stretch, these problems have been fixed in version 10.2.11-2+deb9u1.

We recommend that you upgrade your ceph packages.

For the detailed security status of ceph please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'ceph' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);