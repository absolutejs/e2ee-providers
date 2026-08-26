import { expect, test } from "bun:test";
import { encode, mlsMessageDecoder, mlsMessageEncoder } from "ts-mls";
import {
  MLS_ADAPTER_INTEROP_RECEIPT_SHA256,
  MLS_MESSAGE_VECTOR_SHA256,
  MLS_WORKING_GROUP_VECTOR_REVISION,
  mlsProviderCertification,
} from "../src/certification";

const OFFICIAL_KEY_PACKAGE =
  "000100050001000120c749ea08b3d33784ecf799c150ed8a43580e1cc12a1a893822547ba3c021ac76201e44ee2a27540d5c65a3f1e07bcb2ba558959ad22168d4de7f180201a9b666222038a5e7481e20afe7e500cb3065a67ebe9c2c3ecd537d4479309159fe2215c4b5000105416c696365020001060001000200030200010c00010002000300040005000702000101000000006408842400000000647750340040404cdfef1fdc8d04758353f3f07c2fe7282fa0215ddc72441a33124ef5106df858f86f57aefe08f255450df1243b630b8dd3912cbf2d94af7612fa4a07420cb70d004040136da188e3b773e12e76c9be654f7b51fc94bb8f7d53059e7ce2421d9226e8d1637209d3d65ed1ab0a198e1e63e2052dfdae85609f7d06951cf62ef66a12b300";

test("round-trips the pinned MLS Working Group KeyPackage vector", () => {
  const bytes = Uint8Array.fromHex(OFFICIAL_KEY_PACKAGE);
  const decoded = mlsMessageDecoder(bytes, 0);

  expect(decoded).toBeDefined();
  expect(decoded?.[1]).toBe(bytes.length);
  expect(encode(mlsMessageEncoder, decoded![0])).toEqual(bytes);
});

test("binds certification to immutable vector and interop evidence", async () => {
  expect(mlsProviderCertification.claims).toContain("known-answer-vectors");
  expect(mlsProviderCertification.vectors).toEqual([
    {
      digestSha256: MLS_MESSAGE_VECTOR_SHA256,
      sourceUrl: `https://raw.githubusercontent.com/mlswg/mls-implementations/${MLS_WORKING_GROUP_VECTOR_REVISION}/test-vectors/messages.json`,
    },
  ]);
  expect(mlsProviderCertification.claims).toContain("cross-implementation");
  expect(mlsProviderCertification.implementations).toEqual([
    { name: "ts-mls", version: "2.0.0-rc.16" },
    { name: "OpenMLS", version: "0.9.0" },
  ]);
  const receipt = await Bun.file(
    new URL(
      "../evidence/absolutejs-e2ee-mls-0.4.0-openmls-0.9.0-application.json",
      import.meta.url,
    ),
  ).bytes();
  expect(new Bun.CryptoHasher("sha256").update(receipt).digest("hex")).toBe(
    MLS_ADAPTER_INTEROP_RECEIPT_SHA256,
  );
});
