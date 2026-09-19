import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";

export default [...nextVitals, ...nextTs, { ignores: [".next/**", "out/**", "next-env.d.ts"] }];
