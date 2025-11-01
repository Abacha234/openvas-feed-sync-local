# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845463");
  script_cve_id("CVE-2022-31607", "CVE-2022-31608", "CVE-2022-31615");
  script_tag(name:"creation_date", value:"2022-08-04 01:00:40 +0000 (Thu, 04 Aug 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-5547-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5547-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5547-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nvidia-graphics-drivers-390, nvidia-graphics-drivers-450-server, nvidia-graphics-drivers-470, nvidia-graphics-drivers-470-server, nvidia-graphics-drivers-510, nvidia-graphics-drivers-510-server, nvidia-graphics-drivers-515, nvidia-graphics-drivers-515-server' package(s) announced via the USN-5547-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Le Wu discovered that the NVIDIA graphics drivers did not properly perform
input validation in some situations. A local user could use this to cause a
denial of service or possibly execute arbitrary code. (CVE-2022-31607)

Tal Lossos discovered that the NVIDIA graphics drivers incorrectly handled
certain memory operations, leading to a null-pointer dereference. A local
attacker could use this to cause a denial of service. (CVE-2022-31615)

Artem S. Tashkinov discovered that the NVIDIA graphics drivers Dynamic
Boost D-Bus component did not properly restrict access to its endpoint.
When enabled in non-default configurations, a local attacker could use this
to cause a denial of service or possibly execute arbitrary code.
(CVE-2022-31608)");

  script_tag(name:"affected", value:"'nvidia-graphics-drivers-390, nvidia-graphics-drivers-450-server, nvidia-graphics-drivers-470, nvidia-graphics-drivers-470-server, nvidia-graphics-drivers-510, nvidia-graphics-drivers-510-server, nvidia-graphics-drivers-515, nvidia-graphics-drivers-515-server' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
