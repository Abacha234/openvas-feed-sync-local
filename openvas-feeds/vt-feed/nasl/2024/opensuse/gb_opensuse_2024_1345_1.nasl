# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856091");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-23672", "CVE-2024-24549");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-04-23 01:01:52 +0000 (Tue, 23 Apr 2024)");
  script_name("openSUSE: Security Advisory for tomcat (SUSE-SU-2024:1345-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1345-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/5QWMLGAXIMZ7TJCBH3GIB2CIQPTOSG56");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat'
  package(s) announced via the SUSE-SU-2024:1345-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tomcat fixes the following issues:

  * CVE-2024-24549: Fixed denial of service during header validation for HTTP/2
      stream (bsc#1221386)

  * CVE-2024-23672: Fixed denial of service due to malicious WebSocket client
      keeping connection open (bsc#1221385)

  Other fixes: \- Update to Tomcat 9.0.87

  * Catalina \+ Fix: Minor performance improvement for building filter chains.
  Based on ideas from #702 by Luke Miao. (remm) \+ Fix: Align error handling for
  Writer and OutputStream. Ensure use of either once the response has been
  recycled triggers a NullPointerException provided that discardFacades is
  configured with the default value of true. (markt) \+ Fix: 68692: The standard
  thread pool implementations that are configured using the Executor element now
  implement ExecutorService for better support NIO2. (remm) \+ Fix: 68495: When
  restoring a saved POST request after a successful FORM authentication, ensure
  that neither the URI, the query string nor the protocol are corrupted when
  restoring the request body. (markt) \+ Fix: 68721: Workaround a possible cause
  of duplicate class definitions when using ClassFileTransformers and the
  transformation of a class also triggers the loading of the same class. (markt)
  \+ Fix: The rewrite valve should not do a rewrite if the output is identical to
  the input. (remm) \+ Update: Add a new valveSkip (or VS) rule flag to the
  rewrite valve to allow skipping over the next valve in the Catalina pipeline.
  (remm) \+ Fix: Correct JPMS and OSGi meta-data for tomcat-enbed-core.jar by
  removing reference to org.apache.catalina.ssi package that is no longer included
  in the JAR. Based on pull request #684 by Jendrik Johannes. (markt) \+ Fix: Fix
  ServiceBindingPropertySource so that trailing \r\n sequences are correctly
  removed from files containing property values when configured to do so. Bug
  identified by Coverity Scan. (markt) \+ Add: Add improvements to the CSRF
  prevention filter including the ability to skip adding nonces for resource name
  and subtree URL patterns. (schultz) \+ Fix: Review usage of debug logging and
  downgrade trace or data dumping operations from debug level to trace. (remm) \+
  Fix: 68089: Further improve the performance of request attribute access for
  ApplicationHttpRequest and ApplicationRequest. (markt) \+ Fix: 68559: Allow
  asynchronous error handling to write to the response after an error during
  asynchronous processing. (markt) * Coyote \+ Fix: Improve the HTTP/2 stream
  prioritisation process. If a stream uses all of the connection windows and still
  has ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'tomcat' package(s) on openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
