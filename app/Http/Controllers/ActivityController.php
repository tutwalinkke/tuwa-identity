<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Spatie\Activitylog\Models\Activity;

class ActivityController extends Controller
{
    public function index(Request $request)
    {
        $actor = $request->user();

        $query = Activity::query()
            // Exclude the automatic 'updated' noise from logAll() catching
            // routine attribute touches (e.g. last_login_at) — only show
            // events that were explicitly, meaningfully logged.
            ->where('description', '!=', 'updated')
            ->with(['causer' => function ($q) {
                $q->select('id', 'name', 'email', 'tenant_id');
            }]);

        if (! $actor->hasRole('super-admin')) {
            $tenantUserIds = User::where('tenant_id', $actor->tenant_id)->pluck('id');
            $query->whereIn('causer_id', $tenantUserIds);
        }

        $activities = $query
            ->latest('created_at')
            ->limit(100)
            ->get()
            ->map(function ($activity) {
                return [
                    'id' => $activity->id,
                    'description' => $activity->description,
                    'causer' => $activity->causer ? [
                        'id' => $activity->causer->id,
                        'name' => $activity->causer->name,
                        'email' => $activity->causer->email,
                    ] : null,
                    'subject_type' => $activity->subject_type ? class_basename($activity->subject_type) : null,
                    'subject_id' => $activity->subject_id,
                    'created_at' => $activity->created_at,
                ];
            });

        return response()->json(['activities' => $activities]);
    }
}
