import data from "../../data.json";
import { DataTable } from "@/components/data-table";

export default function LiveURITestingPage() {
  return (
    <div>
      <DataTable data={data} />
    </div>
  );
}
