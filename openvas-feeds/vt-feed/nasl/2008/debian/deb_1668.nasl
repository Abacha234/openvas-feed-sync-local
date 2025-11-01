# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61906");
  script_cve_id("CVE-2008-2378");
  script_tag(name:"creation_date", value:"2008-11-24 22:46:43 +0000 (Mon, 24 Nov 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1668)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1668");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1668");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'hf' package(s) announced via the DSA-1668 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Steve Kemp discovered that hf, an amateur-radio protocol suite using a soundcard as a modem, insecurely tried to execute an external command which could lead to the elevation of privileges for local users.

For the stable distribution (etch), this problem has been fixed in version 0.7.3-4etch1.

For the unstable distribution (sid), this problem has been fixed in version 0.8-8.1.

We recommend that you upgrade your hf package.");

  script_tag(name:"affected", value:"'hf' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);