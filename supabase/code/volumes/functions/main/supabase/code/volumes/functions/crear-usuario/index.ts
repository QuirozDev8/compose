import { serve } from 'https://deno.land/std@0.224.0/http/server.ts'
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.57.4'

const SUPABASE_URL = Deno.env.get('SUPABASE_URL') ?? ''
const SUPABASE_SERVICE_ROLE_KEY =
  Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? ''
const USUARIO_PASSWORD_INICIAL =
  Deno.env.get('USUARIO_PASSWORD_INICIAL') ?? ''

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers':
    'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
}

type CrearUsuarioPayload = {
  correo_corporativo?: unknown
  nombre_completo?: unknown
  cargo?: unknown
  area_id?: unknown
  rol_id?: unknown
}

function jsonResponse(
  body: Record<string, unknown>,
  status = 200,
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      ...corsHeaders,
      'Content-Type': 'application/json; charset=utf-8',
    },
  })
}

function obtenerToken(req: Request): string | null {
  const authorization = req.headers.get('authorization')

  if (!authorization) return null

  const [tipo, token] = authorization.split(' ')

  if (tipo?.toLowerCase() !== 'bearer' || !token) {
    return null
  }

  return token
}

function esCorreoValido(correo: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(correo)
}

serve(async (req: Request) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', {
      status: 200,
      headers: corsHeaders,
    })
  }

  if (req.method !== 'POST') {
    return jsonResponse(
      {
        ok: false,
        codigo: 'METODO_NO_PERMITIDO',
        mensaje: 'Método no permitido.',
      },
      405,
    )
  }

  if (
    !SUPABASE_URL ||
    !SUPABASE_SERVICE_ROLE_KEY ||
    !USUARIO_PASSWORD_INICIAL
  ) {
    console.error('Faltan variables de entorno requeridas.')

    return jsonResponse(
      {
        ok: false,
        codigo: 'CONFIGURACION_INCOMPLETA',
        mensaje:
          'La creación de usuarios no está configurada correctamente.',
      },
      500,
    )
  }

  if (USUARIO_PASSWORD_INICIAL.length < 8) {
    console.error(
      'USUARIO_PASSWORD_INICIAL debe tener al menos 8 caracteres.',
    )

    return jsonResponse(
      {
        ok: false,
        codigo: 'CONFIGURACION_CONTRASENA_INVALIDA',
        mensaje:
          'La contraseña temporal no cumple los requisitos de seguridad.',
      },
      500,
    )
  }

  const token = obtenerToken(req)

  if (!token) {
    return jsonResponse(
      {
        ok: false,
        codigo: 'SESION_REQUERIDA',
        mensaje: 'Debes iniciar sesión para realizar esta acción.',
      },
      401,
    )
  }

  const supabaseAdmin = createClient(
    SUPABASE_URL,
    SUPABASE_SERVICE_ROLE_KEY,
    {
      auth: {
        autoRefreshToken: false,
        persistSession: false,
      },
    },
  )

  /*
   * Validar el JWT con Supabase Auth.
   */
  const {
    data: { user: administradorAuth },
    error: errorAuth,
  } = await supabaseAdmin.auth.getUser(token)

  if (errorAuth || !administradorAuth) {
    console.error('JWT inválido:', errorAuth?.message)

    return jsonResponse(
      {
        ok: false,
        codigo: 'SESION_INVALIDA',
        mensaje: 'La sesión no es válida o ha expirado.',
      },
      401,
    )
  }

  /*
   * Confirmar que la persona autenticada sea un administrador habilitado.
   */
  const { data: perfilAdministrador, error: errorAdministrador } =
    await supabaseAdmin
      .from('user_perfil')
      .select('id, rol_id, acceso_permitido')
      .eq('id', administradorAuth.id)
      .eq('rol_id', 1)
      .eq('acceso_permitido', true)
      .maybeSingle()

  if (errorAdministrador) {
    console.error(
      'Error verificando al administrador:',
      errorAdministrador.message,
    )

    return jsonResponse(
      {
        ok: false,
        codigo: 'ERROR_VALIDANDO_PERMISOS',
        mensaje: 'No fue posible validar los permisos del usuario.',
      },
      500,
    )
  }

  if (!perfilAdministrador) {
    return jsonResponse(
      {
        ok: false,
        codigo: 'PERMISO_DENEGADO',
        mensaje: 'No tienes permisos para crear usuarios.',
      },
      403,
    )
  }

  let payload: CrearUsuarioPayload

  try {
    payload = await req.json()
  } catch {
    return jsonResponse(
      {
        ok: false,
        codigo: 'JSON_INVALIDO',
        mensaje: 'La información enviada no tiene un formato válido.',
      },
      400,
    )
  }

  const correoCorporativo =
    typeof payload.correo_corporativo === 'string'
      ? payload.correo_corporativo.trim().toLowerCase()
      : ''

  const nombreCompleto =
    typeof payload.nombre_completo === 'string'
      ? payload.nombre_completo.trim()
      : ''

  const cargo =
    typeof payload.cargo === 'string'
      ? payload.cargo.trim() || null
      : null

  const areaId =
    typeof payload.area_id === 'string'
      ? payload.area_id.trim()
      : ''

  const rolId =
    typeof payload.rol_id === 'number'
      ? payload.rol_id
      : Number(payload.rol_id)

  if (!correoCorporativo || !esCorreoValido(correoCorporativo)) {
    return jsonResponse(
      {
        ok: false,
        codigo: 'CORREO_INVALIDO',
        mensaje: 'Ingresa un correo corporativo válido.',
      },
      400,
    )
  }

  if (nombreCompleto.length < 3 || nombreCompleto.length > 150) {
    return jsonResponse(
      {
        ok: false,
        codigo: 'NOMBRE_INVALIDO',
        mensaje:
          'El nombre completo debe tener entre 3 y 150 caracteres.',
      },
      400,
    )
  }

  if (!areaId) {
    return jsonResponse(
      {
        ok: false,
        codigo: 'AREA_REQUERIDA',
        mensaje: 'Debes seleccionar un área.',
      },
      400,
    )
  }

  if (!Number.isInteger(rolId)) {
    return jsonResponse(
      {
        ok: false,
        codigo: 'ROL_INVALIDO',
        mensaje: 'Debes seleccionar un rol válido.',
      },
      400,
    )
  }

  /*
   * Validar área y rol antes de crear el usuario en Auth.
   */
  const [
    { data: area, error: errorArea },
    { data: rol, error: errorRol },
    { data: perfilExistente, error: errorPerfilExistente },
  ] = await Promise.all([
    supabaseAdmin
      .from('area')
      .select('id')
      .eq('id', areaId)
      .eq('activo', true)
      .maybeSingle(),

    supabaseAdmin
      .from('rol')
      .select('id')
      .eq('id', rolId)
      .eq('activo', true)
      .maybeSingle(),

    supabaseAdmin
      .from('user_perfil')
      .select('id')
      .eq('correo_corporativo', correoCorporativo)
      .maybeSingle(),
  ])

  if (errorArea || errorRol || errorPerfilExistente) {
    console.error('Error validando información relacionada:', {
      errorArea: errorArea?.message,
      errorRol: errorRol?.message,
      errorPerfilExistente: errorPerfilExistente?.message,
    })

    return jsonResponse(
      {
        ok: false,
        codigo: 'ERROR_VALIDANDO_DATOS',
        mensaje: 'No fue posible validar la información del usuario.',
      },
      500,
    )
  }

  if (!area) {
    return jsonResponse(
      {
        ok: false,
        codigo: 'AREA_NO_DISPONIBLE',
        mensaje: 'El área seleccionada no existe o está inactiva.',
      },
      400,
    )
  }

  if (!rol) {
    return jsonResponse(
      {
        ok: false,
        codigo: 'ROL_NO_DISPONIBLE',
        mensaje: 'El rol seleccionado no existe o está inactivo.',
      },
      400,
    )
  }

  if (perfilExistente) {
    return jsonResponse(
      {
        ok: false,
        codigo: 'CORREO_YA_REGISTRADO',
        mensaje: 'Ya existe un usuario registrado con este correo.',
      },
      409,
    )
  }

  /*
   * Crear el usuario en Supabase Auth con la contraseña temporal.
   * email_confirm=true permite que pueda iniciar sesión inmediatamente.
   */
  const { data: usuarioAuth, error: errorCrearAuth } =
    await supabaseAdmin.auth.admin.createUser({
      email: correoCorporativo,
      password: USUARIO_PASSWORD_INICIAL,
      email_confirm: true,
      user_metadata: {
        nombre_completo: nombreCompleto,
      },
    })

  if (errorCrearAuth || !usuarioAuth.user) {
    console.error(
      'Error creando usuario en Auth:',
      errorCrearAuth?.message,
    )

    const correoDuplicado =
      errorCrearAuth?.message?.toLowerCase().includes('already') ||
      errorCrearAuth?.message?.toLowerCase().includes('registered') ||
      errorCrearAuth?.message?.toLowerCase().includes('exists')

    return jsonResponse(
      {
        ok: false,
        codigo: correoDuplicado
          ? 'CORREO_YA_REGISTRADO'
          : 'ERROR_CREANDO_USUARIO',
        mensaje: correoDuplicado
          ? 'Ya existe un usuario registrado con este correo.'
          : 'No fue posible crear el usuario.',
      },
      correoDuplicado ? 409 : 500,
    )
  }

  const nuevoUsuarioId = usuarioAuth.user.id

  /*
   * Crear el perfil asociado.
   */
  const { error: errorCrearPerfil } = await supabaseAdmin
    .from('user_perfil')
    .insert({
      id: nuevoUsuarioId,
      correo_corporativo: correoCorporativo,
      nombre_completo: nombreCompleto,
      cargo,
      area_id: areaId,
      rol_id: rolId,
      acceso_permitido: true,
      requiere_cambio_contrasena: true,
    })

  if (errorCrearPerfil) {
    console.error(
      'Error creando user_perfil:',
      errorCrearPerfil.message,
    )

    /*
     * Reversión compensatoria:
     * si falla el perfil, eliminar el usuario de Auth para no dejar
     * un registro incompleto.
     */
    const { error: errorRollback } =
      await supabaseAdmin.auth.admin.deleteUser(nuevoUsuarioId)

    if (errorRollback) {
      console.error(
        'Error eliminando usuario incompleto de Auth:',
        errorRollback.message,
      )
    }

    return jsonResponse(
      {
        ok: false,
        codigo: 'ERROR_CREANDO_PERFIL',
        mensaje:
          'No fue posible completar la creación del usuario.',
      },
      500,
    )
  }

  return jsonResponse(
    {
      ok: true,
      codigo: 'USUARIO_CREADO',
      mensaje: 'El usuario fue creado correctamente.',
      usuario: {
        id: nuevoUsuarioId,
        correo_corporativo: correoCorporativo,
        nombre_completo: nombreCompleto,
        cargo,
        area_id: areaId,
        rol_id: rolId,
        acceso_permitido: true,
        requiere_cambio_contrasena: true,
      },
    },
    201,
  )
})
