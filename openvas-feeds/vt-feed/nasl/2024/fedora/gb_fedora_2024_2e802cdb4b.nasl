# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886298");
  script_version("2025-03-11T05:38:16+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"creation_date", value:"2024-03-25 09:38:36 +0000 (Mon, 25 Mar 2024)");
  script_name("Fedora: Security Advisory for python-fastapi (FEDORA-2024-2e802cdb4b)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-2e802cdb4b");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/Q5KMNWUF3QI5S4UUJBVHURB4OXZLVMQU");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-fastapi'
  package(s) announced via the FEDORA-2024-2e802cdb4b advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"FastAPI is a modern, fast (high-performance), web framework for building APIs
with Python 3.7+ based on standard Python type hints.

The key features are:

   Fast: Very high performance, on par with NodeJS and Go (thanks to Starlette
    and Pydantic). One of the fastest Python frameworks available.

   Fast to code: Increase the speed to develop features by about 200% to
    300%.*
   Fewer bugs: Reduce about 40% of human (developer) induced errors.*
   Intuitive: Great editor support. Completion everywhere. Less time
    debugging.
   Easy: Designed to be easy to use and learn. Less time reading docs.
   Short: Minimize code duplication. Multiple features from each parameter
    declaration. Fewer bugs.
   Robust: Get production-ready code. With automatic interactive
    documentation.
   Standards-based: Based on (and fully compatible with) the open standards
    for APIs: OpenAPI (previously known as Swagger) and JSON Schema.

  * estimation based on tests on an internal development team, building
  production applications.");

  script_tag(name:"affected", value:"'python-fastapi' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
