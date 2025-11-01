# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705353");
  script_cve_id("CVE-2023-0767");
  script_tag(name:"creation_date", value:"2023-02-18 02:00:07 +0000 (Sat, 18 Feb 2023)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-5353)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-5353");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5353");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/nss");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'nss' package(s) announced via the DSA-5353 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Christian Holler discovered that incorrect handling of PKCS 12 Safe Bag attributes in nss, the Mozilla Network Security Service library, may result in execution of arbitrary code if a specially crafted PKCS 12 certificate bundle is processed.

For the stable distribution (bullseye), this problem has been fixed in version 2:3.61-1+deb11u3.

We recommend that you upgrade your nss packages.

For the detailed security status of nss please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'nss' package(s) on Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);