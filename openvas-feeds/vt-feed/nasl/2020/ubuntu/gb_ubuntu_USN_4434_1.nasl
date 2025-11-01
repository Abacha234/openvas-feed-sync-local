# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844508");
  script_cve_id("CVE-2019-20839", "CVE-2019-20840", "CVE-2020-14396", "CVE-2020-14397", "CVE-2020-14398", "CVE-2020-14399", "CVE-2020-14400", "CVE-2020-14401", "CVE-2020-14402", "CVE-2020-14403", "CVE-2020-14404", "CVE-2020-14405");
  script_tag(name:"creation_date", value:"2020-07-24 03:00:30 +0000 (Fri, 24 Jul 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-29 00:15:00 +0000 (Sat, 29 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-4434-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4434-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4434-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvncserver' package(s) announced via the USN-4434-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ramin Farajpour Cami discovered that LibVNCServer incorrectly handled
certain malformed unix socket names. A remote attacker could exploit this
with a crafted socket name, leading to a denial of service, or possibly
execute arbitrary code. (CVE-2019-20839)

It was discovered that LibVNCServer did not properly access byte-aligned
data. A remote attacker could possibly use this issue to cause
LibVNCServer to crash, resulting in a denial of service. This issue only
affected Ubuntu 18.04 LTS and Ubuntu 16.04 LTS. (CVE-2019-20840)

Christian Beier discovered that LibVNCServer incorrectly handled anonymous
TLS connections. A remote attacker could possibly use this issue to cause
LibVNCServer to crash, resulting in a denial of service. This issue only
affected Ubuntu 20.04 LTS. (CVE-2020-14396)

It was discovered that LibVNCServer incorrectly handled region clipping. A
remote attacker could possibly use this issue to cause LibVNCServer to
crash, resulting in a denial of service. (CVE-2020-14397)

It was discovered that LibVNCServer did not properly reset incorrectly
terminated TCP connections. A remote attacker could possibly use this
issue to cause an infinite loop, resulting in a denial of service.
(CVE-2020-14398)

It was discovered that LibVNCServer did not properly access byte-aligned
data. A remote attacker could possibly use this issue to cause
LibVNCServer to crash, resulting in a denial of service. (CVE-2020-14399,
CVE-2020-14400)

It was discovered that LibVNCServer incorrectly handled screen scaling on
the server side. A remote attacker could use this issue to cause
LibVNCServer to crash, resulting in a denial of service, or possibly
execute arbitrary code. (CVE-2020-14401)

It was discovered that LibVNCServer incorrectly handled encodings. A
remote attacker could use this issue to cause LibVNCServer to crash,
resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2020-14402, CVE-2020-14403, CVE-2020-14404)

It was discovered that LibVNCServer incorrectly handled TextChat messages.
A remote attacker could possibly use this issue to cause LibVNCServer to
crash, resulting in a denial of service. (CVE-2020-14405)");

  script_tag(name:"affected", value:"'libvncserver' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
