# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704785");
  script_cve_id("CVE-2017-18926");
  script_tag(name:"creation_date", value:"2020-11-08 04:00:05 +0000 (Sun, 08 Nov 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-19 03:15:00 +0000 (Thu, 19 Nov 2020)");

  script_name("Debian: Security Advisory (DSA-4785)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4785");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4785");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/raptor2");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'raptor2' package(s) announced via the DSA-4785 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that raptor2, an RDF parser library, is prone to heap-based buffer overflow flaws, which could result in denial of service, or potentially the execution of arbitrary code, if a specially crafted file is processed.

For the stable distribution (buster), this problem has been fixed in version 2.0.14-1.1~deb10u1.

We recommend that you upgrade your raptor2 packages.

For the detailed security status of raptor2 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'raptor2' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);