# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886486");
  script_version("2024-09-11T05:05:55+0000");
  script_cve_id("CVE-2024-34402", "CVE-2024-34403");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-09-11 05:05:55 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-05-27 10:41:40 +0000 (Mon, 27 May 2024)");
  script_name("Fedora: Security Advisory for uriparser (FEDORA-2024-40e8512956)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-40e8512956");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/UG4J7PD475LSCGCSHFU4GMU4TWLDSNW2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'uriparser'
  package(s) announced via the FEDORA-2024-40e8512956 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Uriparser is a strictly RFC 3986 compliant URI parsing library written
in C. uriparser is cross-platform, fast, supports Unicode and is
licensed under the New BSD license.");

  script_tag(name:"affected", value:"'uriparser' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
