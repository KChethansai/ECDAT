import React from "react";
import { useStore } from "../store.jsx";
import InventoryTable from "../components/InventoryTable.jsx";
import { inventory } from "../lib/selectors.js";
import { PageHead, RequireReport } from "./_shared.jsx";

export default function Inventory() {
  const { report, loading } = useStore();
  return (
    <>
      <PageHead eyebrow="CRYPTOGRAPHIC INVENTORY" title="Inventory" sub="Canonical algorithm families from this scan. Counts are tallies, not scores." />
      <RequireReport report={report} loading={loading} title="NO INVENTORY">
        <InventoryTable inventory={inventory(report)} />
      </RequireReport>
    </>
  );
}
