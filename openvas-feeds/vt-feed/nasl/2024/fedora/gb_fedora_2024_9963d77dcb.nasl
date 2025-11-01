# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886524");
  script_version("2024-09-11T05:05:55+0000");
  script_cve_id("CVE-2024-25629");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-09-11 05:05:55 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-05-27 10:42:40 +0000 (Mon, 27 May 2024)");
  script_name("Fedora: Security Advisory for c-ares (FEDORA-2024-9963d77dcb)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-9963d77dcb");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/CSCMTSPDIE2UHU34TIXQQHZ6JTE3Y3VF");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'c-ares'
  package(s) announced via the FEDORA-2024-9963d77dcb advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"c-ares is a C library that performs DNS requests and name resolves
asynchronously. c-ares is a fork of the library named &#39,ares&#39,, written
by Greg Hudson at MIT.");

  script_tag(name:"affected", value:"'c-ares' package(s) on Fedora 40.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
