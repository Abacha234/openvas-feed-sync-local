# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885812");
  script_version("2024-09-11T05:05:55+0000");
  script_cve_id("CVE-2023-50387", "CVE-2023-4408", "CVE-2023-5517", "CVE-2023-5679", "CVE-2023-50868");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-09-11 05:05:55 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-13 14:15:45 +0000 (Tue, 13 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-02-26 02:03:53 +0000 (Mon, 26 Feb 2024)");
  script_name("Fedora: Security Advisory for bind9-next (FEDORA-2024-499b9be35f)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-499b9be35f");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/RGS7JN6FZXUSTC2XKQHH27574XOULYYJ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind9-next'
  package(s) announced via the FEDORA-2024-499b9be35f advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"BIND (Berkeley Internet Name Domain) is an implementation of the DNS
(Domain Name System) protocols. BIND includes a DNS server (named),
which resolves host names to IP addresses, a resolver library
(routines for applications to use when interfacing with DNS), and
tools for verifying that the DNS server is operating properly.");

  script_tag(name:"affected", value:"'bind9-next' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
