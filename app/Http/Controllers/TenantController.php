<?php

namespace App\Http\Controllers;

use App\Models\Tenant;
use Illuminate\Http\Request;

class TenantController extends Controller
{
    /**
     * Read-only tenant lookup. Only super-admin (which includes the
     * NOC service account) may call this — regular tenant users have
     * no reason to query another tenant's metadata directly.
     */
    public function show(Request $request, int $id)
    {
        if (! $request->user()->hasRole('super-admin')) {
            abort(403, 'Only super-admin may query tenant metadata directly.');
        }

        $tenant = Tenant::findOrFail($id);

        return response()->json(['tenant' => $tenant]);
    }
}
