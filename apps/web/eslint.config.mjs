import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";
import jsdoc from "eslint-plugin-jsdoc";
import tsdoc from "eslint-plugin-tsdoc";

export default [
  ...nextVitals,
  ...nextTs,
  { ignores: [".next/**", "out/**", "next-env.d.ts"] },
  {
    files: ["src/**"],
    ignores: ["src/**/*.test.ts"],
    plugins: { jsdoc, tsdoc },
    rules: {
      "tsdoc/syntax": "error",
      "jsdoc/require-jsdoc": [
        "error",
        {
          publicOnly: true,
          contexts: ["TSInterfaceDeclaration", "TSTypeAliasDeclaration"],
          require: { ClassDeclaration: true, FunctionDeclaration: true, MethodDefinition: true },
        },
      ],
    },
  },
];
