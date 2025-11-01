# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841989");
  script_cve_id("CVE-2014-6051", "CVE-2014-6052", "CVE-2014-6053", "CVE-2014-6054", "CVE-2014-6055");
  script_tag(name:"creation_date", value:"2014-10-01 11:30:28 +0000 (Wed, 01 Oct 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-2365-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2365-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2365-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvncserver' package(s) announced via the USN-2365-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Nicolas Ruff discovered that LibVNCServer incorrectly handled memory when
being advertised large screen sizes by the server. If a user were tricked
into connecting to a malicious server, an attacker could use this issue to
cause a denial of service, or possibly execute arbitrary code.
(CVE-2014-6051, CVE-2014-6052)

Nicolas Ruff discovered that LibVNCServer incorrectly handled large
ClientCutText messages. A remote attacker could use this issue to cause a
server to crash, resulting in a denial of service. (CVE-2014-6053)

Nicolas Ruff discovered that LibVNCServer incorrectly handled zero scaling
factor values. A remote attacker could use this issue to cause a server to
crash, resulting in a denial of service. (CVE-2014-6054)

Nicolas Ruff discovered that LibVNCServer incorrectly handled memory in the
file transfer feature. A remote attacker could use this issue to cause a
server to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2014-6055)");

  script_tag(name:"affected", value:"'libvncserver' package(s) on Ubuntu 12.04, Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
