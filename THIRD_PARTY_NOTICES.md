# Third-party notices

The Apache-2.0 license in this repository covers the project-owned source at
the current revision. It does not replace the licenses of the components below.

## OpenConnect

- Upstream: <https://gitlab.com/openconnect/openconnect>
- Revision: `8b702bf2dbaf11302ed98629214b1df5d50a12aa` (v9.21)
- License: GNU Lesser General Public License v2.1 only (`LGPL-2.1-only`)

The Docker build fetches this exact revision and builds it without carrying its
source files into this Git repository. A distributed binary image must retain
the OpenConnect license and satisfy the LGPL source-availability requirements
for that exact build.

## ocproxy and lwIP

- Upstream: <https://github.com/cernekee/ocproxy>
- Revision: `c98f06d942970cdf35dd66ab46840f7d6d567b60`
- License: BSD 3-Clause (`BSD-3-Clause`)

The Docker builder fetches this exact upstream commit and verifies the checked
out object before compilation. It then applies the repository-carried
`patches/ocproxy-upload-performance.patch`, locked by SHA-256
`beab1230018ac3fc3c9635a060b5c251a4c3707eee51c94425c309a1ed1232bf`.
The patch adds bounded VPNFD backpressure and adjusts lwIP upload buffers; the
modified component remains subject to ocproxy's and lwIP's BSD terms. The
runtime image carries ocproxy's `LICENSE`, `AUTHORS`, and lwIP's `COPYING` under
`/usr/share/licenses/`.

ocproxy/vpnns includes copyright notices for David Edmondson, Kevin Cernekee,
and Google Inc.; the complete notices remain in the fetched source tree and the
runtime `AUTHORS` file.

lwIP includes work copyrighted by the Swedish Institute of Computer Science
and other contributors. Its copyright notices and BSD conditions are fetched
with the locked source and apply independently of this project's license.

## Container packages

Alpine packages and their transitive dependencies remain under their respective
upstream licenses.

## Local-only iSecSP authentication backend

The local authentication backend uses two components extracted from the
official `iSecSP_ubuntu_2.4.0.deb` package supplied to an eligible PKU user:

- `libvl3vpn.so`, SHA-256
  `0a20b9f9760c845e805fdbdded968100344c2cc3026ef1134dd81ae664135787`;
- `libisec.so`, SHA-256
  `cf9df4e6726d95c2f06d38efe5a07684520c90300b147e8915a6c130d7c9469e`.

iSecSP and these libraries are proprietary Array Networks software. The Apache-2.0 license in this repository does not apply to them and grants no right to copy, redistribute, publish, or sublicense them.
The user must obtain the package from an authorized source, review any applicable terms, and build the authentication image locally.

The build statically extracts the two hash-locked libraries and their bundled
third-party notices.

## Names and affiliation

OpenConnect, ocproxy, Array Networks, 北京大学/Peking University, and other
names belong to their respective owners.
