/*
 * Copyright 2018 Dialog LLC <info@dlg.im>
 */

import tls from "tls";
import https from "https";
import { createHash } from "crypto";

export type DomainConfig = {
  domain: string;
  fingerprints: Array<string>;
};

const sha256 = (data: Buffer) =>
  createHash("sha256").update(data).digest("base64");

async function fetchSslPinningConfig({
  host,
  port,
}: URL): Promise<DomainConfig> {
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        host,
        port: parseInt(port, 10) || 443,
      },
      ({ socket }) => {
        if (socket instanceof tls.TLSSocket) {
          const cert = socket.getPeerCertificate(true);
          const fingerprints = [];
          for (let issuer = cert; issuer; issuer = issuer.issuerCertificate) {
            fingerprints.push("sha256/" + sha256(issuer.raw));
            if (issuer === issuer.issuerCertificate) {
              break;
            }
          }

          const domain = cert.subject.CN;

          resolve({ domain, fingerprints });
        } else {
          reject(new Error("Unexpected req.socket type"));
        }
      }
    );

    req.once("error", reject);

    req.end();
  });
}

export default fetchSslPinningConfig;
