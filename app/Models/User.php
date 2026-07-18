<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Hidden;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Sanctum\HasApiTokens;
use Spatie\Permission\Traits\HasRoles;
use Spatie\Activitylog\Traits\LogsActivity;
use Spatie\Activitylog\LogOptions;


#[Fillable([
    'tenant_id',
    'name',
    'email',
    'phone',
    'password',
    'status',
    'last_login_at'
])]

#[Hidden([
    'password',
    'remember_token'
])]

class User extends Authenticatable implements MustVerifyEmail
{
    use HasApiTokens;
    use HasFactory;
    use Notifiable;
    use HasRoles;
    use LogsActivity;


    public function tenant(): BelongsTo
    {
        return $this->belongsTo(Tenant::class);
    }


    public function getActivitylogOptions(): LogOptions
    {
        return LogOptions::defaults()
            ->logAll();
    }


    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'last_login_at' => 'datetime',
            'password' => 'hashed',
        ];
    }
}
