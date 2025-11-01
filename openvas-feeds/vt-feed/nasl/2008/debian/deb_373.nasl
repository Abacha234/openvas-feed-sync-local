# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53661");
  script_cve_id("CVE-2003-0654");
  script_tag(name:"creation_date", value:"2008-01-17 21:36:24 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-373)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-373");
  script_xref(name:"URL", value:"https://www.debian.org/security/2003/dsa-373");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'autorespond' package(s) announced via the DSA-373 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Christian Jaeger discovered a buffer overflow in autorespond, an email autoresponder used with qmail. This vulnerability could potentially be exploited by a remote attacker to gain the privileges of a user who has configured qmail to forward messages to autorespond. This vulnerability is currently not believed to be exploitable due to incidental limits on the length of the problematic input, but there may be situations in which these limits do not apply.

For the stable distribution (woody) this problem has been fixed in version 2.0.2-2woody1.

For the unstable distribution (sid) this problem will be fixed soon.

We recommend that you update your autorespond package.");

  script_tag(name:"affected", value:"'autorespond' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);